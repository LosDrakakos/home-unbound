package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unbound-manager/internal/control"
	"unbound-manager/internal/dnsclient"
	"unbound-manager/internal/model"
	"unbound-manager/internal/store"
	"unbound-manager/internal/supervisor"
	"unbound-manager/internal/web"
)

var version = "dev"

type paths struct{ data, store, local, run, network, seed, root, config, unbound, checkconf, socket string }

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func getPaths() paths {
	d := env("DATA_DIR", "/data")
	run := env("UNBOUND_RUN_DIR", "/run/unbound")
	return paths{data: d, store: filepath.Join(d, "manager/store.json"), local: env("UNBOUND_LOCAL_CONFIG", filepath.Join(d, "unbound/local-records.conf")), run: run, network: env("UNBOUND_NETWORK_CONFIG", filepath.Join(run, "network.conf")), seed: env("UNBOUND_ROOT_KEY_SEED", "/etc/unbound/root.key.seed"), root: filepath.Join(d, "unbound/root.key"), config: env("UNBOUND_CONFIG", "/etc/unbound/unbound.conf"), unbound: env("UNBOUND_BIN", "/usr/local/sbin/unbound"), checkconf: env("UNBOUND_CHECKCONF_BIN", "/usr/local/sbin/unbound-checkconf"), socket: env("UNBOUND_CONTROL_SOCKET", filepath.Join(run, "control.sock"))}
}

type controlCommander interface {
	Command(string) (string, error)
}

func runControlCommand(args []string, commander controlCommander, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("ctl command required")
	}
	response, err := commander.Command(strings.Join(args, " "))
	if err != nil {
		return fmt.Errorf("control command failed: %w", err)
	}
	if _, err := io.WriteString(stdout, response); err != nil {
		return fmt.Errorf("write control response: %w", err)
	}
	return nil
}

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		err = run()
	case "healthcheck":
		err = healthcheck()
	case "ctl":
		p := getPaths()
		err = runControlCommand(os.Args[2:], control.New(p.socket), os.Stdout)
	case "version":
		fmt.Println(version)
		return
	default:
		err = fmt.Errorf("unknown command %q (use run, healthcheck, ctl, or version)", cmd)
	}
	if err != nil {
		log.Printf("unbound-manager: %v", err)
		os.Exit(1)
	}
}

type backend struct {
	mu  sync.Mutex
	st  *store.Store
	p   paths
	ctl *control.Client
}

func (b *backend) Snapshot() model.State { return b.st.Snapshot() }
func (b *backend) GeneratedConfig() (string, error) {
	x, err := os.ReadFile(b.p.local)
	return string(x), err
}
func (b *backend) Command(s string) (string, error) { return b.ctl.Command(s) }
func (b *backend) AddRecord(r model.Record) error {
	return b.apply(func(s *model.State) error { return s.AddRecord(r) })
}
func (b *backend) AddZone(z model.Zone) error {
	return b.apply(func(s *model.State) error { return s.AddZone(z) })
}
func (b *backend) DeleteRecord(id string) error {
	return b.apply(func(s *model.State) error {
		for i, r := range s.Records {
			if r.ID == id {
				s.Records = append(s.Records[:i], s.Records[i+1:]...)
				return nil
			}
		}
		return errors.New("record not found")
	})
}
func (b *backend) DeleteZone(id string) error {
	return b.apply(func(s *model.State) error {
		for i, z := range s.Zones {
			if z.ID == id {
				s.Zones = append(s.Zones[:i], s.Zones[i+1:]...)
				return nil
			}
		}
		return errors.New("zone not found")
	})
}
func (b *backend) UpdateRecord(id string, r model.Record) error {
	return b.apply(func(s *model.State) error {
		idx := -1
		for i, x := range s.Records {
			if x.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errors.New("record not found")
		}
		r.ID = id
		s.Records = append(s.Records[:idx], s.Records[idx+1:]...)
		return s.AddRecord(r)
	})
}
func (b *backend) apply(change func(*model.State) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.st.Snapshot()
	oldConfig, _ := os.ReadFile(b.p.local)
	if err := b.st.Update(change); err != nil {
		return err
	}
	next := b.st.Snapshot()
	rendered, err := model.Render(next)
	if err == nil {
		err = atomicWrite(b.p.local, rendered, 0640)
	}
	if err == nil {
		err = runCheckconf(b.p)
	}
	if err == nil {
		err = b.ctl.Reload()
	}
	if err == nil {
		return nil
	}
	_ = b.st.Replace(old)
	_ = atomicWrite(b.p.local, oldConfig, 0640)
	return fmt.Errorf("apply failed; previous state restored: %w", err)
}

func run() error {
	p := getPaths()
	if err := os.MkdirAll(filepath.Join(p.data, "unbound"), 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(p.data, "manager"), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.run, 0750); err != nil {
		return err
	}
	if err := seedRootKey(p); err != nil {
		return err
	}
	st, err := store.Open(p.store)
	if err != nil {
		return err
	}
	rendered, err := model.Render(st.Snapshot())
	if err != nil {
		return err
	}
	if err = atomicWrite(p.local, rendered, 0640); err != nil {
		return err
	}
	if err = writeNetworkConfig(p); err != nil {
		return err
	}
	if err = runCheckconf(p); err != nil {
		return fmt.Errorf("configuration rejected, refusing to start: %w", err)
	}
	password, err := loadPassword(p)
	if err != nil {
		return err
	}
	ctl := control.New(p.socket)
	b := &backend{st: st, p: p, ctl: ctl}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	sup := supervisor.New(func() *exec.Cmd { return exec.Command(p.unbound, "-d", "-c", p.config) })
	errCh := make(chan error, 2)
	go func() { errCh <- sup.Run(ctx) }()
	var srv *http.Server
	if strings.ToLower(env("UI_ENABLED", "true")) != "false" {
		h, err := web.New(web.Config{Password: password, Backend: b, DNSAddress: env("DNS_ADDRESS", "127.0.0.1:53")})
		if err != nil {
			cancel()
			return err
		}
		srv = &http.Server{Addr: env("UI_LISTEN", ":8080"), Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
		go func() {
			e := srv.ListenAndServe()
			if errors.Is(e, http.ErrServerClosed) {
				e = nil
			}
			errCh <- e
		}()
	}
	first := <-errCh
	if ctx.Err() == nil && first != nil {
		cancel()
	}
	if ctx.Err() == nil && srv != nil && first == nil {
		cancel()
	}
	if srv != nil {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}
	if ctx.Err() != nil {
		return nil
	}
	return first
}

func healthcheck() error {
	p := getPaths()
	if _, err := control.New(p.socket).Command("status"); err != nil {
		return fmt.Errorf("control status: %w", err)
	}
	r, err := dnsclient.Query(env("DNS_ADDRESS", "127.0.0.1:53"), "localhost.", "A")
	if err != nil {
		return fmt.Errorf("local DNS query: %w", err)
	}
	return validateHealthDNS(r)
}
func validateHealthDNS(r dnsclient.Result) error {
	if r.RCode != 0 {
		return fmt.Errorf("localhost query rcode %d", r.RCode)
	}
	for _, answer := range r.Answers {
		if answer.Type == "A" && answer.Value == "127.0.0.1" {
			return nil
		}
	}
	return errors.New("localhost query did not return 127.0.0.1")
}
func runCheckconf(p paths) error {
	cmd := exec.Command(p.checkconf, p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unbound-checkconf: %w", err)
	}
	return nil
}
func seedRootKey(p paths) error {
	if _, err := os.Stat(p.root); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	src, err := os.Open(p.seed)
	if err != nil {
		return fmt.Errorf("open trust-anchor seed: %w", err)
	}
	defer src.Close()
	b, err := io.ReadAll(io.LimitReader(src, 1<<20))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("trust-anchor seed is empty")
	}
	return atomicWrite(p.root, b, 0640)
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = d.Sync()
		d.Close()
	}
	if err != nil {
		return err
	}
	ok = true
	return nil
}

func writeNetworkConfig(p paths) error {
	mode := strings.ToLower(env("DNS_IPV6", "auto"))
	if mode != "auto" && mode != "yes" && mode != "no" {
		return errors.New("DNS_IPV6 must be auto, yes, or no")
	}
	ipv6 := mode == "yes"
	if mode == "auto" {
		c, err := net.ListenPacket("udp6", "[::]:0")
		ipv6 = err == nil
		if c != nil {
			c.Close()
		}
	}
	body := "# Generated by unbound-manager. DO NOT EDIT.\nserver:\n  interface: 0.0.0.0\n"
	if ipv6 {
		body += "  interface: ::0\n  do-ip6: yes\n"
	} else {
		body += "  do-ip6: no\n"
	}
	return atomicWrite(p.network, []byte(body), 0640)
}
func loadPassword(p paths) (string, error) {
	if v := os.Getenv("UI_PASSWORD"); v != "" {
		return v, nil
	}
	if f := os.Getenv("UI_PASSWORD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", errors.New("UI_PASSWORD_FILE is empty")
		}
		return v, nil
	}
	path := filepath.Join(p.data, "manager/ui-password")
	if b, err := os.ReadFile(path); err == nil {
		log.Printf("UI password is stored at %s", path)
		return strings.TrimSpace(string(b)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	v := base64.RawURLEncoding.EncodeToString(raw)
	if err := atomicWrite(path, []byte(v+"\n"), 0600); err != nil {
		return "", err
	}
	log.Printf("generated UI password: %s", v)
	log.Printf("stored at %s; it will not be logged again", path)
	return v, nil
}

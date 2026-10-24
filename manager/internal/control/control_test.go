package control

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixProtocolAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("sandbox forbids unix sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line == "UBCT1 status\n" {
				c.Write([]byte("version: 1.26.2\nthreads: 1\n"))
			} else {
				c.Write([]byte("error unknown command\n"))
			}
			c.Close()
		}
	}()
	cl := New(path)
	out, err := cl.Command("status")
	if err != nil || !strings.Contains(out, "version") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := cl.Command("nope"); err == nil {
		t.Fatal("error response accepted")
	}
	<-done
}

func TestCommandInjectionRejected(t *testing.T) {
	cl := New(filepath.Join(t.TempDir(), "missing"))
	if _, err := cl.Command("status\nstop"); err == nil {
		t.Fatal("newline command accepted")
	}
}

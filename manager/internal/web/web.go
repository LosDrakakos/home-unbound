package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unbound-manager/internal/dnsclient"
	"unbound-manager/internal/model"
)

//go:embed templates/*.html static/*.css
var assets embed.FS

type Backend interface {
	Snapshot() model.State
	AddRecord(model.Record) error
	DeleteRecord(string) error
	AddZone(model.Zone) error
	DeleteZone(string) error
	Command(string) (string, error)
	GeneratedConfig() (string, error)
}
type Config struct {
	Password   string
	Backend    Backend
	DNSAddress string
}
type session struct {
	CSRF    string
	Expires time.Time
	Flash   string
}
type Server struct {
	password   [32]byte
	backend    Backend
	dnsAddress string
	templates  *template.Template
	static     http.Handler
	sessions   map[string]*session
	mu         sync.Mutex
	failures   map[string][]time.Time
}
type pageData struct {
	Title, CSRF, Flash, Error, Status, Stats, Forwards, Config, ZonesLive, DataLive string
	Current                                                                         string
	State                                                                           model.State
	PTRs                                                                            []ptrView
	Lookup                                                                          *dnsclient.Result
	LookupName, LookupType                                                          string
	Override                                                                        string
	RecursiveOK, DNSSECOK                                                           bool
	Record                                                                          *model.Record
	Submitted                                                                       map[string]string
}
type ptrView struct{ IP, Name, Kind string }

func New(c Config) (http.Handler, error) {
	if c.Password == "" {
		return nil, errors.New("UI password is required")
	}
	if c.Backend == nil {
		return nil, errors.New("backend is required")
	}
	t, err := template.New("ui").Funcs(template.FuncMap{
		"listTypes": func() []string { return []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR"} },
		"zoneLabel": func(v string) string {
			return map[string]string{"transparent": "Add my records; resolve the rest normally", "static": "Private domain — only my records exist", "redirect": "Wildcard — use apex records for subdomains", "always_nxdomain": "Block (NXDOMAIN)", "always_refuse": "Block (REFUSED)"}[v]
		},
		"inputValue": func(values map[string]string, key string, fallback any) string {
			if values != nil {
				if value, ok := values[key]; ok {
					return value
				}
			}
			return fmt.Sprint(fallback)
		},
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	sub, _ := fs.Sub(assets, "static")
	s := &Server{password: sha256.Sum256([]byte(c.Password)), backend: c.Backend, dnsAddress: c.DNSAddress, templates: t, static: http.FileServer(http.FS(sub)), sessions: map[string]*session{}, failures: map[string][]time.Time{}}
	if s.dnsAddress == "" {
		s.dnsAddress = "127.0.0.1:53"
	}
	m := http.NewServeMux()
	m.Handle("GET /static/", http.StripPrefix("/static/", s.static))
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.login)
	m.HandleFunc("POST /logout", s.requireSession(s.logout))
	m.HandleFunc("GET /healthz", s.health)
	m.HandleFunc("GET /", s.requireSession(s.dashboard))
	m.HandleFunc("GET /records", s.requireSession(s.records))
	m.HandleFunc("POST /records", s.requireSession(s.addRecord))
	m.HandleFunc("POST /records/{id}/delete", s.requireSession(s.deleteRecord))
	m.HandleFunc("GET /records/{id}/edit", s.requireSession(s.editRecordPage))
	m.HandleFunc("POST /records/{id}/edit", s.requireSession(s.editRecord))
	m.HandleFunc("GET /reverse", s.requireSession(s.reverse))
	m.HandleFunc("GET /zones", s.requireSession(s.zones))
	m.HandleFunc("POST /zones", s.requireSession(s.addZone))
	m.HandleFunc("POST /zones/{id}/delete", s.requireSession(s.deleteZone))
	m.HandleFunc("GET /lookup", s.requireSession(s.lookup))
	m.HandleFunc("POST /lookup", s.requireSession(s.lookup))
	m.HandleFunc("GET /config", s.requireSession(s.liveConfig))
	m.HandleFunc("GET /maintenance", s.requireSession(s.maintenance))
	m.HandleFunc("POST /maintenance", s.requireSession(s.maintenance))
	m.HandleFunc("GET /api/records", s.apiAuth(s.apiRecords))
	m.HandleFunc("POST /api/records", s.apiAuth(s.apiRecords))
	m.HandleFunc("DELETE /api/records/{id}", s.apiAuth(s.apiDeleteRecord))
	m.HandleFunc("GET /api/zones", s.apiAuth(s.apiZones))
	m.HandleFunc("POST /api/zones", s.apiAuth(s.apiZones))
	m.HandleFunc("DELETE /api/zones/{id}", s.apiAuth(s.apiDeleteZone))
	m.HandleFunc("GET /api/status", s.apiAuth(s.apiStatus))
	return s.headers(m), nil
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func secureEqual(password string, want [32]byte) bool {
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
func (s *Server) getSession(r *http.Request) (string, *session) {
	now := time.Now()
	s.mu.Lock()
	s.purgeLocked(now)
	s.mu.Unlock()
	c, err := r.Cookie("unbound_session")
	if err != nil {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.sessions[c.Value]
	if v == nil || now.After(v.Expires) {
		delete(s.sessions, c.Value)
		return "", nil
	}
	return c.Value, v
}
func (s *Server) purgeLocked(now time.Time) {
	for id, sess := range s.sessions {
		if sess == nil || now.After(sess.Expires) {
			delete(s.sessions, id)
		}
	}
	for key, entries := range s.failures {
		recent := entries[:0]
		for _, entry := range entries {
			if now.Sub(entry) < time.Minute {
				recent = append(recent, entry)
			}
		}
		if len(recent) == 0 {
			delete(s.failures, key)
		} else {
			s.failures[key] = recent
		}
	}
}
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, sess := s.getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !s.safeOrigin(r) || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(sess.CSRF)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}
func (s *Server) safeOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		return origin == "http://"+r.Host || origin == "https://"+r.Host
	}
	ref := r.Header.Get("Referer")
	return ref == "" || strings.HasPrefix(ref, "http://"+r.Host+"/") || strings.HasPrefix(ref, "https://"+r.Host+"/")
}
func (s *Server) clientKey(r *http.Request) string {
	p := r.RemoteAddr
	if i := strings.LastIndex(p, ":"); i >= 0 {
		return p[:i]
	}
	return p
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", pageData{Title: "Login"})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	key := s.clientKey(r)
	if !s.safeOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.purgeLocked(time.Now())
	s.mu.Unlock()
	if !secureEqual(r.FormValue("password"), s.password) {
		s.mu.Lock()
		now := time.Now()
		s.purgeLocked(now)
		recent := s.failures[key]
		recent = append(recent, now)
		s.failures[key] = recent
		s.mu.Unlock()
		time.Sleep(time.Duration(min(len(recent), 5)) * 100 * time.Millisecond)
		s.renderStatus(w, "login.html", pageData{Title: "Login", Error: "Invalid password"}, http.StatusUnauthorized)
		return
	}
	id := token()
	sess := &session{CSRF: token(), Expires: time.Now().Add(12 * time.Hour)}
	s.mu.Lock()
	s.sessions[id] = sess
	delete(s.failures, key)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "unbound_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	id, _ := s.getSession(r)
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "unbound_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) data(r *http.Request, title string) pageData {
	_, sess := s.getSession(r)
	current := "dashboard"
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/records"):
		current = "records"
	case strings.HasPrefix(path, "/reverse"):
		current = "reverse"
	case strings.HasPrefix(path, "/zones"):
		current = "zones"
	case strings.HasPrefix(path, "/lookup"):
		current = "lookup"
	case strings.HasPrefix(path, "/config"):
		current = "config"
	case strings.HasPrefix(path, "/maintenance"):
		current = "maintenance"
	}
	d := pageData{Title: title, Current: current, State: s.backend.Snapshot()}
	if sess != nil {
		d.CSRF = sess.CSRF
		s.mu.Lock()
		d.Flash = sess.Flash
		sess.Flash = ""
		s.mu.Unlock()
	}
	return d
}
func (s *Server) flash(r *http.Request, msg string) {
	_, sess := s.getSession(r)
	if sess != nil {
		s.mu.Lock()
		sess.Flash = msg
		s.mu.Unlock()
	}
}
func (s *Server) render(w http.ResponseWriter, name string, d pageData) {
	s.renderStatus(w, name, d, http.StatusOK)
}
func (s *Server) renderStatus(w http.ResponseWriter, name string, d pageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, d); err != nil {
		fmt.Fprintf(w, "template error: %v", err)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if _, err := s.backend.Command("status"); err != nil {
		http.Error(w, "unbound unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Dashboard")
	d.Status, _ = s.backend.Command("status")
	d.Stats, _ = s.backend.Command("stats_noreset")
	var forwardsErr, modulesErr error
	d.Forwards, forwardsErr = s.backend.Command("list_forwards")
	modules, modulesErr := s.backend.Command("get_option module-config")
	d.RecursiveOK = forwardsErr == nil && strings.TrimSpace(d.Forwards) == ""
	d.DNSSECOK = modulesErr == nil && hasModule(modules, "validator")
	s.render(w, "dashboard.html", d)
}
func (s *Server) records(w http.ResponseWriter, r *http.Request) {
	s.render(w, "records.html", s.data(r, "Records"))
}
func parseNumber(r *http.Request, name string, bits int) (uint64, bool, error) {
	raw := strings.TrimSpace(r.FormValue(name))
	if raw == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(raw, 10, bits)
	if err != nil {
		return 0, true, fmt.Errorf("%s must be a number from 0 to %d", name, (uint64(1)<<bits)-1)
	}
	return v, true, nil
}
func recordFromForm(r *http.Request) (model.Record, error) {
	record := model.Record{Name: r.FormValue("name"), Type: r.FormValue("type"), Value: r.FormValue("value"), Comment: r.FormValue("comment"), PTR: r.FormValue("ptr") != "", Exchange: r.FormValue("exchange"), Target: r.FormValue("target")}
	ttl, ttlSet, err := parseNumber(r, "ttl", 32)
	if err != nil {
		return record, err
	}
	if ttl > model.MaxTTL {
		return record, fmt.Errorf("ttl must be a number from 0 to %d", model.MaxTTL)
	}
	pref, _, err := parseNumber(r, "preference", 16)
	if err != nil {
		return record, err
	}
	pri, _, err := parseNumber(r, "priority", 16)
	if err != nil {
		return record, err
	}
	weight, _, err := parseNumber(r, "weight", 16)
	if err != nil {
		return record, err
	}
	port, _, err := parseNumber(r, "port", 16)
	if err != nil {
		return record, err
	}
	record.TTL = uint32(ttl)
	record.TTLSet = ttlSet
	record.Preference = uint16(pref)
	record.Priority = uint16(pri)
	record.Weight = uint16(weight)
	record.Port = uint16(port)
	return record, nil
}
func submittedValues(r *http.Request) map[string]string {
	_ = r.ParseForm()
	out := map[string]string{}
	for key, values := range r.Form {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}
	return out
}
func (s *Server) addRecord(w http.ResponseWriter, r *http.Request) {
	record, err := recordFromForm(r)
	if err == nil {
		err = s.backend.AddRecord(record)
	}
	if err != nil {
		d := s.data(r, "Records")
		d.Error = err.Error()
		d.Record = &record
		d.Submitted = submittedValues(r)
		s.renderStatus(w, "records.html", d, http.StatusBadRequest)
		return
	}
	s.flash(r, "Record added and Unbound reloaded")
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}
func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.DeleteRecord(r.PathValue("id")); err != nil {
		d := s.data(r, "Records")
		d.Error = err.Error()
		s.renderStatus(w, "records.html", d, http.StatusBadRequest)
		return
	}
	s.flash(r, "Record deleted")
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}
func (s *Server) editRecordPage(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Edit record")
	for i := range d.State.Records {
		if d.State.Records[i].ID == r.PathValue("id") {
			d.Record = &d.State.Records[i]
			break
		}
	}
	if d.Record == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "record-edit.html", d)
}
func (s *Server) editRecord(w http.ResponseWriter, r *http.Request) {
	record, parseErr := recordFromForm(r)
	record.ID = r.PathValue("id")
	if parseErr != nil {
		d := s.data(r, "Edit record")
		d.Record = &record
		d.Submitted = submittedValues(r)
		d.Error = parseErr.Error()
		s.renderStatus(w, "record-edit.html", d, http.StatusBadRequest)
		return
	}
	if u, ok := s.backend.(interface {
		UpdateRecord(string, model.Record) error
	}); ok {
		if err := u.UpdateRecord(r.PathValue("id"), record); err != nil {
			d := s.data(r, "Edit record")
			d.Record = &record
			d.Submitted = submittedValues(r)
			d.Error = err.Error()
			s.renderStatus(w, "record-edit.html", d, http.StatusBadRequest)
			return
		}
	} else {
		d := s.data(r, "Edit record")
		d.Record = &record
		d.Submitted = submittedValues(r)
		d.Error = "editing unavailable"
		s.renderStatus(w, "record-edit.html", d, http.StatusNotImplemented)
		return
	}
	s.flash(r, "Record updated")
	http.Redirect(w, r, "/records", 303)
}
func (s *Server) reverse(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Reverse DNS")
	for _, x := range d.State.Records {
		if x.Type == "PTR" {
			ip := x.Name
			if parsed, err := model.ReverseToIP(x.Name); err == nil {
				ip = parsed
			}
			d.PTRs = append(d.PTRs, ptrView{IP: ip, Name: x.Value, Kind: "explicit"})
		} else if x.PTR {
			d.PTRs = append(d.PTRs, ptrView{IP: x.Value, Name: x.Name, Kind: "automatic"})
		}
	}
	s.render(w, "reverse.html", d)
}
func (s *Server) zones(w http.ResponseWriter, r *http.Request) {
	s.render(w, "zones.html", s.data(r, "Zones"))
}
func (s *Server) addZone(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.AddZone(model.Zone{Name: r.FormValue("name"), Type: r.FormValue("type"), Comment: r.FormValue("comment")}); err != nil {
		d := s.data(r, "Zones")
		d.Error = err.Error()
		s.renderStatus(w, "zones.html", d, 400)
		return
	}
	s.flash(r, "Zone added")
	http.Redirect(w, r, "/zones", 303)
}
func (s *Server) deleteZone(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.DeleteZone(r.PathValue("id")); err != nil {
		d := s.data(r, "Zones")
		d.Error = err.Error()
		s.renderStatus(w, "zones.html", d, http.StatusBadRequest)
		return
	}
	s.flash(r, "Zone deleted")
	http.Redirect(w, r, "/zones", 303)
}
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Lookup / Verify")
	if r.Method == "POST" {
		d.LookupName = r.FormValue("name")
		d.LookupType = r.FormValue("type")
		res, err := dnsclient.Query(s.dnsAddress, d.LookupName, d.LookupType)
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Lookup = &res
			if n, e := model.NormalizeName(d.LookupName); e == nil {
				for _, x := range d.State.Records {
					autoReverse := ""
					if x.PTR && (x.Type == "A" || x.Type == "AAAA") {
						autoReverse, _ = model.ReverseName(x.Value)
					}
					if x.Name == n || autoReverse == n {
						d.Override = "This name has a local record override."
						break
					}
				}
				if d.Override == "" {
					for _, z := range d.State.Zones {
						prefix := strings.TrimSuffix(n, z.Name)
						if n == z.Name || strings.HasSuffix(prefix, ".") {
							d.Override = "This name is affected by local zone " + z.Name + " (" + z.Type + ")."
							break
						}
					}
				}
			}
		}
	}
	s.render(w, "lookup.html", d)
}
func (s *Server) liveConfig(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Live config")
	d.Config, _ = s.backend.GeneratedConfig()
	d.ZonesLive, _ = s.backend.Command("list_local_zones")
	d.DataLive, _ = s.backend.Command("list_local_data")
	s.render(w, "config.html", d)
}
func (s *Server) maintenance(w http.ResponseWriter, r *http.Request) {
	d := s.data(r, "Maintenance")
	if r.Method == "POST" {
		action := r.FormValue("action")
		cmd := ""
		switch action {
		case "flush_name":
			if n, err := model.NormalizeName(r.FormValue("name")); err == nil {
				cmd = "flush_zone " + n
			} else {
				d.Error = err.Error()
			}
		case "flush_all":
			cmd = "flush_zone ."
		case "flush_bogus":
			cmd = "flush_bogus"
		}
		if cmd != "" {
			if _, err := s.backend.Command(cmd); err != nil {
				d.Error = err.Error()
			} else {
				d.Flash = "Maintenance command completed"
			}
		}
	}
	s.render(w, "maintenance.html", d)
}

func (s *Server) apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		basic := false
		if _, p, ok := r.BasicAuth(); ok && secureEqual(p, s.password) {
			basic = true
		} else {
			_, sess := s.getSession(r)
			if sess == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="unbound-manager"`)
				http.Error(w, "authentication required", 401)
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" {
				if !s.safeOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
					http.Error(w, "invalid CSRF token", 403)
					return
				}
			}
		}
		if basic && !s.safeOrigin(r) {
			http.Error(w, "cross-origin request rejected", 403)
			return
		}
		next(w, r)
	}
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		http.Error(w, "Content-Type must be application/json", 415)
		return false
	}
	return true
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !requireJSON(w, r) {
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, err.Error(), 400)
		return false
	}
	return true
}
func (s *Server) apiRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		jsonOut(w, 200, s.backend.Snapshot().Records)
		return
	}
	var x model.Record
	if !decodeJSON(w, r, &x) {
		return
	}
	x.ID = ""
	if err := x.Normalize(); err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	if err := s.backend.AddRecord(x); err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	st := s.backend.Snapshot()
	for _, v := range st.Records {
		if v.ID == x.ID {
			x = v
		}
	}
	jsonOut(w, 201, x)
}
func (s *Server) apiDeleteRecord(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.DeleteRecord(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	jsonOut(w, 200, map[string]bool{"deleted": true})
}
func (s *Server) apiZones(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		jsonOut(w, 200, s.backend.Snapshot().Zones)
		return
	}
	var x model.Zone
	if !decodeJSON(w, r, &x) {
		return
	}
	x.ID = ""
	if err := x.Normalize(); err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	if err := s.backend.AddZone(x); err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	st := s.backend.Snapshot()
	for _, v := range st.Zones {
		if v.ID == x.ID {
			x = v
		}
	}
	jsonOut(w, 201, x)
}
func (s *Server) apiDeleteZone(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.DeleteZone(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	jsonOut(w, 200, map[string]bool{"deleted": true})
}
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.backend.Command("status")
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	stats, _ := s.backend.Command("stats_noreset")
	forwards, forwardsErr := s.backend.Command("list_forwards")
	modules, modulesErr := s.backend.Command("get_option module-config")
	jsonOut(w, 200, map[string]any{"status": status, "stats": stats, "recursive": forwardsErr == nil && strings.TrimSpace(forwards) == "", "dnssec_validation": modulesErr == nil && hasModule(modules, "validator")})
}
func hasModule(value, want string) bool {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') })
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

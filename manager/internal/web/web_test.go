package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unbound-manager/internal/model"
)

type fakeBackend struct {
	state           model.State
	commands        []string
	addErr          error
	deleteRecordErr error
	updateErr       error
	deleteZoneErr   error
	moduleConfig    string
	forwards        string
}

func (f *fakeBackend) Snapshot() model.State { return f.state }
func (f *fakeBackend) AddRecord(r model.Record) error {
	if f.addErr != nil {
		return f.addErr
	}
	return f.state.AddRecord(r)
}
func (f *fakeBackend) DeleteRecord(id string) error {
	if f.deleteRecordErr != nil {
		return f.deleteRecordErr
	}
	for i, r := range f.state.Records {
		if r.ID == id {
			f.state.Records = append(f.state.Records[:i], f.state.Records[i+1:]...)
			return nil
		}
	}
	return nil
}
func (f *fakeBackend) AddZone(z model.Zone) error { return f.state.AddZone(z) }
func (f *fakeBackend) DeleteZone(string) error    { return f.deleteZoneErr }
func (f *fakeBackend) UpdateRecord(_ string, r model.Record) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	return nil
}
func (f *fakeBackend) Command(s string) (string, error) {
	f.commands = append(f.commands, s)
	if s == "status" {
		return "version: 1.26.2\nuptime: 42\n", nil
	}
	if s == "stats_noreset" {
		return "total.num.queries=10\ntotal.num.cachehits=8\n", nil
	}
	if s == "get_option module-config" {
		if f.moduleConfig == "" {
			return "validator iterator", nil
		}
		return f.moduleConfig, nil
	}
	if s == "list_forwards" {
		return f.forwards, nil
	}
	return "", nil
}
func (f *fakeBackend) GeneratedConfig() (string, error) { return "server:\n", nil }

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	h, _ := newTestSetup(t, &fakeBackend{state: model.State{Version: model.StoreVersion}})
	return h
}
func newTestSetup(t *testing.T, backend *fakeBackend) (http.Handler, *fakeBackend) {
	t.Helper()
	h, err := New(Config{Password: "secret", Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	return h, backend
}
func perform(h http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	v := url.Values{"password": {"secret"}}.Encode()
	r := httptest.NewRequest("POST", "http://example.test/login", strings.NewReader(v))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login=%d", w.Code)
	}
	return w.Result().Cookies()[0]
}

func csrfToken(t *testing.T, h http.Handler, cookie *http.Cookie, path string) string {
	t.Helper()
	page := perform(h, "GET", "http://example.test"+path, cookie)
	needle := "name=\"csrf_token\" value=\""
	i := strings.Index(page.Body.String(), needle)
	if i < 0 {
		t.Fatalf("csrf token missing from %s", path)
	}
	i += len(needle)
	j := strings.Index(page.Body.String()[i:], "\"")
	return page.Body.String()[i : i+j]
}

func postForm(h http.Handler, path string, cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://example.test"+path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestLoginRequired(t *testing.T) {
	h := newTestHandler(t)
	r := perform(h, "GET", "http://example.test/records", nil)
	if r.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", r.Code)
	}
	r = perform(h, "GET", "http://example.test/api/records", nil)
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("api status=%d", r.Code)
	}
}
func TestCSRFMandatoryAndRecordFlow(t *testing.T) {
	h := newTestHandler(t)
	cookie := login(t, h)
	v := url.Values{"name": {"x.example"}, "type": {"A"}, "value": {"192.0.2.1"}}.Encode()
	req := httptest.NewRequest("POST", "http://example.test/records", strings.NewReader(v))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no csrf=%d", w.Code)
	}
	page := perform(h, "GET", "http://example.test/records", cookie)
	body := page.Body.String()
	needle := "name=\"csrf_token\" value=\""
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatal("csrf not found")
	}
	i += len(needle)
	j := strings.Index(body[i:], "\"")
	token := body[i : i+j]
	v = url.Values{"csrf_token": {token}, "name": {"x.example"}, "type": {"A"}, "value": {"192.0.2.1"}}.Encode()
	req = httptest.NewRequest("POST", "http://example.test/records", strings.NewReader(v))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("add=%d body=%s", w.Code, w.Body.String())
	}
}
func TestAPIBasicAuthAndJSON(t *testing.T) {
	h := newTestHandler(t)
	clientID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	payload, _ := json.Marshal(model.Record{ID: clientID, Name: "api.example", Type: "A", Value: "192.0.2.4"})
	req := httptest.NewRequest("POST", "http://example.test/api/records", bytes.NewReader(payload))
	req.SetBasicAuth("anything", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var created model.Record
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == clientID || len(created.ID) != 32 {
		t.Fatalf("server did not replace client ID: %q", created.ID)
	}
	zonePayload, _ := json.Marshal(model.Zone{ID: clientID, Name: "api-zone.example", Type: "static"})
	zoneReq := httptest.NewRequest("POST", "http://example.test/api/zones", bytes.NewReader(zonePayload))
	zoneReq.SetBasicAuth("anything", "secret")
	zoneReq.Header.Set("Content-Type", "application/json")
	zoneW := httptest.NewRecorder()
	h.ServeHTTP(zoneW, zoneReq)
	if zoneW.Code != http.StatusCreated {
		t.Fatalf("zone status=%d body=%s", zoneW.Code, zoneW.Body.String())
	}
	var zone model.Zone
	if err := json.Unmarshal(zoneW.Body.Bytes(), &zone); err != nil {
		t.Fatal(err)
	}
	if zone.ID == clientID || len(zone.ID) != 32 {
		t.Fatalf("server did not replace zone ID: %q", zone.ID)
	}
}
func TestSecurityHeaders(t *testing.T) {
	h := newTestHandler(t)
	r := perform(h, "GET", "http://example.test/login", nil)
	for _, name := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if r.Header().Get(name) == "" {
			t.Errorf("missing %s", name)
		}
	}
	if got := r.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
}

func TestCrossOriginProtectionOnWrites(t *testing.T) {
	tests := []struct {
		name, origin, fetchSite string
		wantAllowed             bool
	}{
		{name: "browser same origin with null origin", origin: "null", fetchSite: "same-origin", wantAllowed: true},
		{name: "browser cross site", fetchSite: "cross-site", wantAllowed: false},
		{name: "evil origin fallback", origin: "http://evil.example", wantAllowed: false},
		{name: "non browser client", wantAllowed: true},
	}
	setOriginHeaders := func(r *http.Request, test struct {
		name, origin, fetchSite string
		wantAllowed             bool
	}) {
		if test.origin != "" {
			r.Header.Set("Origin", test.origin)
		}
		if test.fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", test.fetchSite)
		}
	}

	for _, test := range tests {
		t.Run("login/"+test.name, func(t *testing.T) {
			h := newTestHandler(t)
			body := url.Values{"password": {"secret"}}.Encode()
			r := httptest.NewRequest("POST", "http://example.test/login", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			setOriginHeaders(r, test)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusForbidden
			if test.wantAllowed {
				want = http.StatusSeeOther
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d; body=%s", w.Code, want, w.Body.String())
			}
		})

		t.Run("session record form/"+test.name, func(t *testing.T) {
			h := newTestHandler(t)
			cookie := login(t, h)
			csrf := csrfToken(t, h, cookie, "/records")
			body := url.Values{"csrf_token": {csrf}, "name": {"origin.example"}, "type": {"A"}, "value": {"192.0.2.20"}}.Encode()
			r := httptest.NewRequest("POST", "http://example.test/records", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(cookie)
			setOriginHeaders(r, test)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusForbidden
			if test.wantAllowed {
				want = http.StatusSeeOther
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d; body=%s", w.Code, want, w.Body.String())
			}
		})

		t.Run("API Basic write/"+test.name, func(t *testing.T) {
			h := newTestHandler(t)
			payload := []byte(`{"name":"api-origin.example","type":"A","value":"192.0.2.21"}`)
			r := httptest.NewRequest("POST", "http://example.test/api/records", bytes.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			r.SetBasicAuth("admin", "secret")
			setOriginHeaders(r, test)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusForbidden
			if test.wantAllowed {
				want = http.StatusCreated
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d; body=%s", w.Code, want, w.Body.String())
			}
		})

		t.Run("API session write/"+test.name, func(t *testing.T) {
			h := newTestHandler(t)
			cookie := login(t, h)
			csrf := csrfToken(t, h, cookie, "/records")
			payload := []byte(`{"name":"api-session-origin.example","type":"A","value":"192.0.2.22"}`)
			r := httptest.NewRequest("POST", "http://example.test/api/records", bytes.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.AddCookie(cookie)
			setOriginHeaders(r, test)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusForbidden
			if test.wantAllowed {
				want = http.StatusCreated
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d; body=%s", w.Code, want, w.Body.String())
			}
		})
	}
}

func TestRecordFromFormRejectsInvalidNumbersAndIgnoresID(t *testing.T) {
	for field, value := range map[string]string{"ttl": "abc", "preference": "-1", "priority": "70000", "weight": "oops", "port": "99999"} {
		v := url.Values{"id": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "name": {"form.example"}, "type": {"A"}, "value": {"192.0.2.1"}, field: {value}}
		r := httptest.NewRequest("POST", "http://example.test/records", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := recordFromForm(r); err == nil {
			t.Errorf("invalid %s=%q accepted", field, value)
		}
	}
	v := url.Values{"id": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "name": {"form.example"}, "type": {"A"}, "value": {"192.0.2.1"}}
	r := httptest.NewRequest("POST", "http://example.test/records", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	record, err := recordFromForm(r)
	if err != nil {
		t.Fatal(err)
	}
	if record.ID != "" {
		t.Fatalf("client form ID retained: %q", record.ID)
	}
	if record.TTLSet || record.TTL != 0 {
		t.Fatalf("empty TTL was not left for defaulting: %+v", record)
	}
}

func TestInvalidNumericFormIsShownAsHTML(t *testing.T) {
	h := newTestHandler(t)
	cookie := login(t, h)
	token := csrfToken(t, h, cookie, "/records")
	w := postForm(h, "/records", cookie, url.Values{"csrf_token": {token}, "name": {"bad-number.example"}, "type": {"A"}, "value": {"192.0.2.1"}, "ttl": {"abc"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "ttl must be a number") || !strings.Contains(w.Body.String(), "bad-number.example") {
		t.Fatalf("numeric error not rendered with submitted input: status=%d type=%q body=%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestEditAndDeleteErrorsRenderHTML(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	b := &fakeBackend{state: model.State{Version: model.StoreVersion, Records: []model.Record{{ID: id, Name: "old.example.", Type: "A", Value: "192.0.2.1", TTL: 3600, TTLSet: true}}}, updateErr: errors.New("reload rejected"), deleteRecordErr: errors.New("delete rejected")}
	h, _ := newTestSetup(t, b)
	cookie := login(t, h)
	token := csrfToken(t, h, cookie, "/records")
	w := postForm(h, "/records/"+id+"/edit", cookie, url.Values{"csrf_token": {token}, "name": {"edited.example"}, "type": {"A"}, "value": {"203.0.113.8"}, "ttl": {"300"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "reload rejected") || !strings.Contains(w.Body.String(), "203.0.113.8") {
		t.Fatalf("edit error response status=%d type=%q body=%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	w = postForm(h, "/records/"+id+"/delete", cookie, url.Values{"csrf_token": {token}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "delete rejected") {
		t.Fatalf("delete error response status=%d type=%q body=%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestDNSSECStatusDerivedFromModuleConfig(t *testing.T) {
	b := &fakeBackend{state: model.State{Version: model.StoreVersion}, moduleConfig: "iterator", forwards: "forward.example. IN forward"}
	h, _ := newTestSetup(t, b)
	req := httptest.NewRequest("GET", "http://example.test/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["dnssec_validation"] != false || status["recursive"] != false {
		t.Fatalf("status was hardcoded: %#v", status)
	}
	cookie := login(t, h)
	page := perform(h, "GET", "http://example.test/", cookie)
	if !strings.Contains(page.Body.String(), "DNSSEC validation is not enabled") || !strings.Contains(page.Body.String(), "forwarders are configured") {
		t.Fatalf("dashboard warnings missing: %s", page.Body.String())
	}
}

func TestSessionAndFailureMapsArePurged(t *testing.T) {
	now := time.Now()
	s := &Server{sessions: map[string]*session{"valid": {Expires: now.Add(time.Hour)}, "expired": {Expires: now.Add(-time.Hour)}}, failures: map[string][]time.Time{"old": {now.Add(-2 * time.Minute)}, "mixed": {now.Add(-2 * time.Minute), now}}}
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: "unbound_session", Value: "valid"})
	if _, sess := s.getSession(r); sess == nil {
		t.Fatal("valid session lost")
	}
	if _, ok := s.sessions["expired"]; ok {
		t.Fatal("expired session not purged")
	}
	if _, ok := s.failures["old"]; ok {
		t.Fatal("old failure bucket not purged")
	}
	if len(s.failures["mixed"]) != 1 {
		t.Fatalf("old failure entries remain: %#v", s.failures)
	}
}

func TestRecordsPageHasUsableNoJSControls(t *testing.T) {
	h, _ := newTestSetup(t, &fakeBackend{state: model.State{Version: model.StoreVersion, Records: []model.Record{{ID: "0123456789abcdef0123456789abcdef", Name: "nas.home.arpa.", Type: "A", Value: "192.168.1.10", TTL: 3600, Comment: "NAS", PTR: true}}}})
	cookie := login(t, h)
	page := perform(h, "GET", "http://example.test/records", cookie)
	body := page.Body.String()
	for _, want := range []string{"record-type-help", "class=\"f-mx", "class=\"f-srv", "class=\"f-ptr", "<details", "aria-current=\"page\"", "Changes apply immediately"} {
		if !strings.Contains(body, want) {
			t.Errorf("records page missing %q", want)
		}
	}
}

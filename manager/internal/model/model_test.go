package model

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":            "example.com.",
		"_sip._tcp.Example.com.": "_sip._tcp.example.com.",
		"@":                      ".",
	} {
		got, err := NormalizeName(in)
		if err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "bad name", "-bad.example", "bad-.example", "a..example", "bad\nlocal-data: evil", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 250) + ".com"}
	for _, in := range bad {
		if _, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) unexpectedly succeeded", in)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct{ in, typ, want string }{{"192.0.2.1", "A", "192.0.2.1"}, {"::ffff:192.0.2.1", "A", "192.0.2.1"}, {"2001:db8::1", "AAAA", "2001:db8::1"}}
	for _, tc := range cases {
		got, err := NormalizeIP(tc.in, tc.typ)
		if err != nil || got != tc.want {
			t.Errorf("NormalizeIP(%q,%q)=%q,%v", tc.in, tc.typ, got, err)
		}
	}
	for _, tc := range []struct{ in, typ string }{{"192.0.2.1", "AAAA"}, {"2001:db8::1", "A"}, {"fe80::1%eth0", "AAAA"}, {"not-ip", "A"}} {
		if _, err := NormalizeIP(tc.in, tc.typ); err == nil {
			t.Errorf("NormalizeIP(%q,%q) succeeded", tc.in, tc.typ)
		}
	}
}

func TestReverseName(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.10":  "10.2.0.192.in-addr.arpa.",
		"2001:db8::1": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		got, err := ReverseName(in)
		if err != nil || got != want {
			t.Errorf("ReverseName(%q)=%q,%v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"192.0.2.10", "2001:db8::1"} {
		reverse, _ := ReverseName(in)
		got, err := ReverseToIP(reverse)
		if err != nil || got != in {
			t.Errorf("ReverseToIP(%q)=%q,%v; want %q", reverse, got, err, in)
		}
	}
}

func TestRecordValidationAndInjection(t *testing.T) {
	valid := []Record{
		{Name: "host.example", Type: "A", Value: "192.0.2.1", PTR: true},
		{Name: "host.example", Type: "AAAA", Value: "2001:db8::1"},
		{Name: "alias.example", Type: "CNAME", Value: "host.example"},
		{Name: "txt.example", Type: "TXT", Value: "printable text"},
		{Name: "example", Type: "MX", Preference: 10, Exchange: "mail.example"},
		{Name: "_sip._tcp.example", Type: "SRV", Priority: 1, Weight: 2, Port: 5060, Target: "sip.example"},
		{Name: "192.0.2.9", Type: "PTR", Value: "host.example"},
	}
	for i := range valid {
		if err := valid[i].Normalize(); err != nil {
			t.Errorf("valid %+v: %v", valid[i], err)
		}
	}
	for _, value := range []string{"quote\"", "single'", "slash\\", "line\nbreak", "tab\tbad"} {
		r := Record{Name: "txt.example", Type: "TXT", Value: value}
		if err := r.Normalize(); err == nil {
			t.Errorf("TXT injection %q accepted", value)
		}
	}
	r := Record{Name: "bad\nname", Type: "A", Value: "192.0.2.1"}
	if err := r.Normalize(); err == nil {
		t.Fatal("newline name accepted")
	}
	r = Record{Name: "x.example", Type: "TXT", Value: strings.Repeat("x", 1025)}
	if err := r.Normalize(); err == nil {
		t.Fatal("oversize TXT accepted")
	}
	for _, root := range []string{".", "@"} {
		r = Record{Name: root, Type: "A", Value: "192.0.2.1"}
		if err := r.Normalize(); err == nil {
			t.Errorf("root record name %q accepted", root)
		}
	}
}

func TestConflictRules(t *testing.T) {
	s := State{Version: StoreVersion}
	a := Record{ID: "1", Name: "x.example", Type: "A", Value: "192.0.2.1", PTR: true}
	if err := s.AddRecord(a); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRecord(Record{ID: "2", Name: "x.example", Type: "CNAME", Value: "target.example"}); err == nil {
		t.Fatal("CNAME coexistence accepted")
	}
	if err := s.AddRecord(Record{ID: "3", Name: "y.example", Type: "A", Value: "192.0.2.1", PTR: true}); err == nil {
		t.Fatal("duplicate auto PTR accepted")
	}
	if err := s.AddRecord(Record{ID: "4", Name: "192.0.2.1", Type: "PTR", Value: "ptr.example"}); err == nil {
		t.Fatal("explicit PTR collision accepted")
	}
	if err := s.AddRecord(Record{ID: "5", Name: "x.example", Type: "A", Value: "192.0.2.1", PTR: false}); err == nil {
		t.Fatal("duplicate record accepted")
	}
}

func TestZoneValidation(t *testing.T) {
	for _, typ := range []string{"transparent", "static", "redirect", "always_nxdomain", "always_refuse"} {
		z := Zone{Name: "example", Type: typ}
		if err := z.Normalize(); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
	z := Zone{Name: "example", Type: "nodefault"}
	if err := z.Normalize(); err == nil {
		t.Fatal("invalid zone type accepted")
	}
	for _, root := range []string{".", "@"} {
		z = Zone{Name: root, Type: "always_nxdomain"}
		if err := z.Normalize(); err == nil {
			t.Errorf("root zone name %q accepted", root)
		}
	}
}

func TestStateRejectsMalformedIDs(t *testing.T) {
	bad := []string{"", "1", strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)}
	for _, id := range bad {
		s := State{Version: StoreVersion, Records: []Record{{ID: id, Name: "id.example", Type: "A", Value: "192.0.2.1"}}}
		if err := s.Validate(); err == nil {
			t.Errorf("record ID %q accepted", id)
		}
	}
	s := State{Version: StoreVersion, Zones: []Zone{{ID: "0123456789abcdef0123456789abcdef", Name: "valid.example", Type: "static"}}}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid ID rejected: %v", err)
	}
}

func TestTTLDefaultAndExplicitZero(t *testing.T) {
	defaulted := Record{Name: "default.example", Type: "A", Value: "192.0.2.1"}
	if err := defaulted.Normalize(); err != nil {
		t.Fatal(err)
	}
	if defaulted.TTL != DefaultTTL {
		t.Fatalf("default TTL=%d", defaulted.TTL)
	}
	explicit := Record{Name: "zero.example", Type: "A", Value: "192.0.2.2", TTL: 0, TTLSet: true}
	if err := explicit.Normalize(); err != nil {
		t.Fatal(err)
	}
	if explicit.TTL != 0 {
		t.Fatalf("explicit TTL=%d", explicit.TTL)
	}
}

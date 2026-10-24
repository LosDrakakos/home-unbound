package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderGolden(t *testing.T) {
	s := State{Version: StoreVersion,
		Zones: []Zone{{ID: "00000000000000000000000000000002", Name: "blocked.example", Type: "always_nxdomain"}, {ID: "00000000000000000000000000000001", Name: "home.arpa", Type: "static"}},
		Records: []Record{
			{ID: "00000000000000000000000000000004", Name: "txt.example", Type: "TXT", Value: "a long " + string(make([]byte, 0))},
			{ID: "00000000000000000000000000000001", Name: "nas.home.arpa", Type: "A", Value: "192.168.77.10", TTL: 3600, PTR: true},
			{ID: "00000000000000000000000000000003", Name: "example", Type: "MX", Preference: 10, Exchange: "mail.example", TTL: 300},
			{ID: "00000000000000000000000000000002", Name: "10.0.0.53", Type: "PTR", Value: "dns.home.arpa", TTL: 120},
		},
	}
	for i := range s.Zones {
		if err := s.Zones[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	for i := range s.Records {
		if err := s.Records[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "local-records.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("render mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestTXTSplitting(t *testing.T) {
	r := Record{ID: "00000000000000000000000000000001", Name: "txt.example", Type: "TXT", Value: string(make([]byte, 256))}
	for i := range r.Value {
		_ = i
	}
	r.Value = ""
	for i := 0; i < 256; i++ {
		r.Value += "x"
	}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, err := Render(State{Version: StoreVersion, Records: []Record{r}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("empty render")
	}
}

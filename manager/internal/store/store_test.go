package store

import (
	"os"
	"path/filepath"
	"testing"
	"unbound-manager/internal/model"
)

func TestAtomicPersistenceAndReload(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "manager", "store.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := model.Record{Name: "host.example", Type: "A", Value: "192.0.2.2"}
	if err := s.Update(func(st *model.State) error { return st.AddRecord(r) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Snapshot().Records) != 1 {
		t.Fatalf("records=%d", len(s2.Snapshot().Records))
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains: %v", err)
	}
}

func TestOpenRejectsMalformedIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	data := `{"version":1,"records":[{"id":"bad","name":"host.example","type":"A","value":"192.0.2.1","ttl":3600}],"zones":[]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("malformed persisted ID accepted")
	}
}

func TestUpdateRollbackOnError(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := s.Snapshot()
	errSentinel := os.ErrInvalid
	if err := s.Update(func(st *model.State) error {
		st.Records = append(st.Records, model.Record{ID: "bad"})
		return errSentinel
	}); err == nil {
		t.Fatal("wanted error")
	}
	if len(s.Snapshot().Records) != len(want.Records) {
		t.Fatal("state changed after failed update")
	}
}

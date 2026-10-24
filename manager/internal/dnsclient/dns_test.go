package dnsclient

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildQueryHasRDAndEDNSDO(t *testing.T) {
	b, id, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 29 || binary.BigEndian.Uint16(b[:2]) != id {
		t.Fatal("bad id")
	}
	if binary.BigEndian.Uint16(b[2:4])&0x0100 == 0 {
		t.Fatal("RD missing")
	}
	if binary.BigEndian.Uint16(b[10:12]) != 1 {
		t.Fatal("OPT missing")
	}
	found := false
	for i := 0; i+5 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 41 && binary.BigEndian.Uint32(b[i+5:i+9])&0x8000 != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("DO missing")
	}
}

func TestParseCompressedAnswers(t *testing.T) {
	q, id, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	// Replace OPT count with one answer and append compressed owner A answer.
	binary.BigEndian.PutUint16(q[6:8], 1)
	binary.BigEndian.PutUint16(q[10:12], 0)
	// Strip the 11-byte root OPT.
	q = q[:len(q)-11]
	q = append(q, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8)
	binary.BigEndian.PutUint16(q[:2], id)
	q[3] |= 0x80
	q[3] |= 0x20 // response + AD
	r, err := ParseResponse(q, id)
	if err != nil {
		t.Fatal(err)
	}
	if !r.AD || r.RCode != 0 || len(r.Answers) != 1 || r.Answers[0].Value != netip.MustParseAddr("192.0.2.8").String() {
		t.Fatalf("%+v", r)
	}
}

func TestParseNameCompressionLoop(t *testing.T) {
	b := make([]byte, 14)
	binary.BigEndian.PutUint16(b[:2], 7)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b[12] = 0xc0
	b[13] = 0x0c
	if _, err := ParseResponse(b, 7); err == nil {
		t.Fatal("compression loop accepted")
	}
}

package dnsclient

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var types = map[string]uint16{"A": 1, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}

type Answer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}
type Result struct {
	RCode   int      `json:"rcode"`
	AD      bool     `json:"ad"`
	Answers []Answer `json:"answers"`
}

func BuildQuery(name, typ string) ([]byte, uint16, error) {
	qtype, ok := types[strings.ToUpper(typ)]
	if !ok {
		return nil, 0, errors.New("unsupported query type")
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		name = "."
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[10:], 1)
	if name == "." {
		b = append(b, 0)
	} else {
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, 0, errors.New("invalid DNS name")
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	b = append(b, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0)
	return b, id, nil
}

func Query(addr, name, typ string) (Result, error) {
	q, id, err := BuildQuery(name, typ)
	if err != nil {
		return Result{}, err
	}
	c, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return Result{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write(q); err != nil {
		return Result{}, err
	}
	b := make([]byte, 65535)
	n, err := c.Read(b)
	if err != nil {
		return Result{}, err
	}
	if n >= 4 && b[2]&2 != 0 {
		return queryTCP(addr, q, id)
	}
	return ParseResponse(b[:n], id)
}
func queryTCP(addr string, q []byte, id uint16) (Result, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return Result{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	h := []byte{byte(len(q) >> 8), byte(len(q))}
	if _, err = c.Write(append(h, q...)); err != nil {
		return Result{}, err
	}
	if _, err = io.ReadFull(c, h); err != nil {
		return Result{}, err
	}
	n := int(binary.BigEndian.Uint16(h))
	b := make([]byte, n)
	if _, err = io.ReadFull(c, b); err != nil {
		return Result{}, err
	}
	return ParseResponse(b, id)
}

func ParseResponse(b []byte, id uint16) (Result, error) {
	if len(b) < 12 {
		return Result{}, errors.New("short DNS packet")
	}
	if binary.BigEndian.Uint16(b) != id {
		return Result{}, errors.New("DNS transaction ID mismatch")
	}
	r := Result{RCode: int(b[3] & 15), AD: b[3]&0x20 != 0}
	off := 12
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	for i := 0; i < qd; i++ {
		_, n, err := readName(b, off)
		if err != nil {
			return r, err
		}
		off = n
		if off+4 > len(b) {
			return r, errors.New("short question")
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		name, n, err := readName(b, off)
		if err != nil {
			return r, err
		}
		off = n
		if off+10 > len(b) {
			return r, errors.New("short answer")
		}
		typ := binary.BigEndian.Uint16(b[off:])
		ttl := binary.BigEndian.Uint32(b[off+4:])
		l := int(binary.BigEndian.Uint16(b[off+8:]))
		start := off + 10
		end := start + l
		if end > len(b) {
			return r, errors.New("short rdata")
		}
		value, tname, err := formatRData(b, typ, start, end)
		if err != nil {
			return r, err
		}
		r.Answers = append(r.Answers, Answer{Name: name, Type: tname, TTL: ttl, Value: value})
		off = end
	}
	return r, nil
}

func readName(b []byte, off int) (string, int, error) {
	if off >= len(b) {
		return "", off, errors.New("name outside packet")
	}
	labels := []string{}
	next := -1
	seen := map[int]bool{}
	steps := 0
	for {
		if off >= len(b) {
			return "", off, errors.New("truncated name")
		}
		if seen[off] || steps > len(b) {
			return "", off, errors.New("DNS compression loop")
		}
		seen[off] = true
		steps++
		n := int(b[off])
		if n&0xc0 == 0xc0 {
			if off+1 >= len(b) {
				return "", off, errors.New("truncated pointer")
			}
			ptr := int(n&0x3f)<<8 | int(b[off+1])
			if next < 0 {
				next = off + 2
			}
			off = ptr
			continue
		}
		if n&0xc0 != 0 {
			return "", off, errors.New("invalid label")
		}
		off++
		if n == 0 {
			if next < 0 {
				next = off
			}
			break
		}
		if n > 63 || off+n > len(b) {
			return "", off, errors.New("invalid label length")
		}
		labels = append(labels, string(b[off:off+n]))
		off += n
	}
	if len(labels) == 0 {
		return ".", next, nil
	}
	return strings.Join(labels, ".") + ".", next, nil
}

func formatRData(b []byte, typ uint16, start, end int) (string, string, error) {
	switch typ {
	case 1:
		if end-start != 4 {
			return "", "A", errors.New("bad A rdata")
		}
		a := netip.AddrFrom4([4]byte(b[start:end]))
		return a.String(), "A", nil
	case 28:
		if end-start != 16 {
			return "", "AAAA", errors.New("bad AAAA rdata")
		}
		var x [16]byte
		copy(x[:], b[start:end])
		return netip.AddrFrom16(x).String(), "AAAA", nil
	case 5, 12:
		n, _, err := readName(b, start)
		if typ == 5 {
			return n, "CNAME", err
		}
		return n, "PTR", err
	case 15:
		if end-start < 3 {
			return "", "MX", errors.New("bad MX rdata")
		}
		n, _, err := readName(b, start+2)
		return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(b[start:]), n), "MX", err
	case 33:
		if end-start < 7 {
			return "", "SRV", errors.New("bad SRV rdata")
		}
		n, _, err := readName(b, start+6)
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b[start:]), binary.BigEndian.Uint16(b[start+2:]), binary.BigEndian.Uint16(b[start+4:]), n), "SRV", err
	case 16:
		parts := []string{}
		for start < end {
			n := int(b[start])
			start++
			if start+n > end {
				return "", "TXT", errors.New("bad TXT rdata")
			}
			parts = append(parts, strconv.Quote(string(b[start:start+n])))
			start += n
		}
		return strings.Join(parts, " "), "TXT", nil
	case 6:
		return "SOA data", "SOA", nil
	default:
		return fmt.Sprintf("%x", b[start:end]), strconv.Itoa(int(typ)), nil
	}
}

package model

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const StoreVersion = 1
const DefaultTTL = 3600
const MaxTTL = 604800

type Record struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	TTLSet     bool   `json:"-"`
	Comment    string `json:"comment,omitempty"`
	PTR        bool   `json:"ptr,omitempty"`
	Preference uint16 `json:"preference,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	Priority   uint16 `json:"priority,omitempty"`
	Weight     uint16 `json:"weight,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	Target     string `json:"target,omitempty"`
}

func (r *Record) UnmarshalJSON(data []byte) error {
	var v struct {
		ID         string  `json:"id"`
		Name       string  `json:"name"`
		Type       string  `json:"type"`
		Value      string  `json:"value"`
		TTL        *uint32 `json:"ttl"`
		Comment    string  `json:"comment"`
		PTR        bool    `json:"ptr"`
		Preference uint16  `json:"preference"`
		Exchange   string  `json:"exchange"`
		Priority   uint16  `json:"priority"`
		Weight     uint16  `json:"weight"`
		Port       uint16  `json:"port"`
		Target     string  `json:"target"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	*r = Record{ID: v.ID, Name: v.Name, Type: v.Type, Value: v.Value, Comment: v.Comment, PTR: v.PTR, Preference: v.Preference, Exchange: v.Exchange, Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: v.Target}
	if v.TTL != nil {
		r.TTL = *v.TTL
		r.TTLSet = true
	}
	return nil
}

type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Comment string `json:"comment,omitempty"`
}
type State struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
	Zones   []Zone   `json:"zones"`
}

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func NormalizeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "@" || s == "." {
		return ".", nil
	}
	if s == "" || strings.ContainsAny(s, "\r\n\t \"'\\") {
		return "", errors.New("hostname is empty or contains unsafe characters")
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) > 253 {
		return "", errors.New("hostname exceeds 253 characters")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return "", errors.New("hostname labels must be 1..63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname labels may not start or end with '-'")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("invalid hostname character %q", r)
			}
		}
	}
	return s + ".", nil
}

func NormalizeIP(s, typ string) (string, error) {
	if strings.Contains(s, "%") {
		return "", errors.New("IP address zones are not allowed")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", errors.New("invalid IP address")
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	switch strings.ToUpper(typ) {
	case "A":
		if !a.Is4() {
			return "", errors.New("A requires IPv4")
		}
	case "AAAA":
		if !a.Is6() {
			return "", errors.New("AAAA requires IPv6")
		}
	default:
		return "", errors.New("invalid address record type")
	}
	return a.String(), nil
}

func ReverseName(s string) (string, error) {
	if strings.Contains(s, "%") {
		return "", errors.New("IP address zones are not allowed")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", errors.New("invalid IP address")
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0]), nil
	}
	b := a.As16()
	parts := make([]string, 0, 32)
	for i := 15; i >= 0; i-- {
		parts = append(parts, strconv.FormatUint(uint64(b[i]&15), 16), strconv.FormatUint(uint64(b[i]>>4), 16))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}

func ReverseToIP(name string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if strings.HasSuffix(n, ".in-addr.arpa") {
		labels := strings.Split(strings.TrimSuffix(n, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return "", errors.New("invalid IPv4 reverse name")
		}
		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}
		a, err := netip.ParseAddr(strings.Join(labels, "."))
		if err != nil || !a.Is4() {
			return "", errors.New("invalid IPv4 reverse name")
		}
		return a.String(), nil
	}
	if strings.HasSuffix(n, ".ip6.arpa") {
		labels := strings.Split(strings.TrimSuffix(n, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return "", errors.New("invalid IPv6 reverse name")
		}
		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}
		for _, x := range labels {
			if len(x) != 1 || !strings.Contains("0123456789abcdef", x) {
				return "", errors.New("invalid IPv6 reverse name")
			}
		}
		hex := strings.Join(labels, "")
		groups := make([]string, 8)
		for i := range groups {
			groups[i] = hex[i*4 : i*4+4]
		}
		a, err := netip.ParseAddr(strings.Join(groups, ":"))
		if err != nil {
			return "", errors.New("invalid IPv6 reverse name")
		}
		return a.String(), nil
	}
	return "", errors.New("not a reverse DNS name")
}

func normalizePTRName(s string) (string, error) {
	if r, err := ReverseName(s); err == nil {
		return r, nil
	}
	n, err := NormalizeName(s)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(n, ".in-addr.arpa.") && !strings.HasSuffix(n, ".ip6.arpa.") {
		return "", errors.New("PTR name must be an IP address or reverse DNS name")
	}
	return n, nil
}

func (r *Record) Normalize() error {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.TTL == 0 && !r.TTLSet {
		r.TTL = DefaultTTL
	}
	if r.TTL > MaxTTL {
		return errors.New("TTL exceeds 604800")
	}
	var err error
	if r.Type == "PTR" {
		r.Name, err = normalizePTRName(r.Name)
	} else {
		r.Name, err = NormalizeName(r.Name)
	}
	if err != nil {
		return err
	}
	if r.Name == "." {
		return errors.New("record name may not be the DNS root")
	}
	switch r.Type {
	case "A", "AAAA":
		r.Value, err = NormalizeIP(r.Value, r.Type)
	case "CNAME":
		r.Value, err = NormalizeName(r.Value)
	case "PTR":
		r.Value, err = NormalizeName(r.Value)
	case "TXT":
		if len(r.Value) > 1024 {
			return errors.New("TXT value exceeds 1024 bytes")
		}
		if r.Value == "" {
			return errors.New("TXT value is empty")
		}
		for _, c := range r.Value {
			if c > unicode.MaxASCII || !unicode.IsPrint(c) || c == 34 || c == 39 || c == 92 {
				return errors.New("TXT permits printable ASCII except quotes and backslash")
			}
		}
	case "MX":
		r.Exchange, err = NormalizeName(r.Exchange)
		if err == nil && r.Exchange == "." {
			err = errors.New("MX exchange is required")
		}
	case "SRV":
		r.Target, err = NormalizeName(r.Target)
		if err == nil && r.Target == "." {
			err = errors.New("SRV target is required")
		}
	default:
		return errors.New("type must be A, AAAA, CNAME, TXT, MX, SRV, or PTR")
	}
	return err
}

func (z *Zone) Normalize() error {
	if z.ID == "" {
		z.ID = NewID()
	}
	n, err := NormalizeName(z.Name)
	if err != nil {
		return err
	}
	z.Name = n
	if z.Name == "." {
		return errors.New("local zone name may not be the DNS root")
	}
	z.Type = strings.ToLower(strings.TrimSpace(z.Type))
	switch z.Type {
	case "transparent", "static", "redirect", "always_nxdomain", "always_refuse":
		return nil
	}
	return errors.New("invalid local-zone type")
}

func (s *State) normalizeVersion() {
	if s.Version == 0 {
		s.Version = StoreVersion
	}
}
func (s *State) Validate() error {
	s.normalizeVersion()
	if s.Version != StoreVersion {
		return fmt.Errorf("unsupported store version %d", s.Version)
	}
	fresh := State{Version: s.Version}
	for _, z := range s.Zones {
		if !validID(z.ID) {
			return fmt.Errorf("invalid zone ID %q", z.ID)
		}
		if err := fresh.AddZone(z); err != nil {
			return err
		}
	}
	for _, r := range s.Records {
		if !validID(r.ID) {
			return fmt.Errorf("invalid record ID %q", r.ID)
		}
		if err := fresh.AddRecord(r); err != nil {
			return err
		}
	}
	s.Records = fresh.Records
	s.Zones = fresh.Zones
	return nil
}

func (s *State) AddRecord(r Record) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	s.normalizeVersion()
	newReverse := ""
	if r.PTR && (r.Type == "A" || r.Type == "AAAA") {
		newReverse, _ = ReverseName(r.Value)
	}
	if r.Type == "PTR" {
		newReverse = r.Name
	}
	for _, e := range s.Records {
		if e.ID == r.ID {
			return errors.New("duplicate record ID")
		}
		if e.Name == r.Name && (e.Type == "CNAME" || r.Type == "CNAME") {
			return errors.New("CNAME may not coexist with records at the same name")
		}
		if recordKey(e) == recordKey(r) {
			return errors.New("duplicate identical record")
		}
		eReverse := ""
		if e.PTR && (e.Type == "A" || e.Type == "AAAA") {
			eReverse, _ = ReverseName(e.Value)
		}
		if e.Type == "PTR" {
			eReverse = e.Name
		}
		if newReverse != "" && eReverse == newReverse {
			return errors.New("PTR collision for IP address")
		}
	}
	s.Records = append(s.Records, r)
	return nil
}
func recordKey(r Record) string {
	return strings.Join([]string{r.Name, r.Type, r.Value, strconv.Itoa(int(r.Preference)), r.Exchange, strconv.Itoa(int(r.Priority)), strconv.Itoa(int(r.Weight)), strconv.Itoa(int(r.Port)), r.Target}, "|")
}
func (s *State) AddZone(z Zone) error {
	if err := z.Normalize(); err != nil {
		return err
	}
	s.normalizeVersion()
	for _, e := range s.Zones {
		if e.ID == z.ID || e.Name == z.Name {
			return errors.New("duplicate local zone")
		}
	}
	s.Zones = append(s.Zones, z)
	return nil
}
func (s State) Clone() State {
	out := s
	out.Records = append([]Record(nil), s.Records...)
	out.Zones = append([]Zone(nil), s.Zones...)
	return out
}

func Render(s State) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	lines := []string{"# Generated by unbound-manager. DO NOT EDIT.", "server:"}
	zs := append([]Zone(nil), s.Zones...)
	sort.Slice(zs, func(i, j int) bool { return zs[i].Name < zs[j].Name })
	for _, z := range zs {
		lines = append(lines, fmt.Sprintf("  local-zone: \"%s\" %s", z.Name, z.Type))
	}
	data := []string{}
	for _, r := range s.Records {
		if r.PTR && (r.Type == "A" || r.Type == "AAAA") {
			data = append(data, fmt.Sprintf("  local-data-ptr: \"%s %d %s\"", r.Value, r.TTL, r.Name))
		}
		data = append(data, renderRecord(r))
	}
	sort.Strings(data)
	lines = append(lines, data...)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
func renderRecord(r Record) string {
	head := fmt.Sprintf("%s %d IN %s ", r.Name, r.TTL, r.Type)
	var val string
	switch r.Type {
	case "A", "AAAA", "CNAME", "PTR":
		val = r.Value
	case "TXT":
		chunks := []string{}
		for len(r.Value) > 255 {
			chunks = append(chunks, "\""+r.Value[:255]+"\"")
			r.Value = r.Value[255:]
		}
		chunks = append(chunks, "\""+r.Value+"\"")
		return "  local-data: '" + head + strings.Join(chunks, " ") + "'"
	case "MX":
		val = fmt.Sprintf("%d %s", r.Preference, r.Exchange)
	case "SRV":
		val = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
	}
	return "  local-data: \"" + head + val + "\""
}

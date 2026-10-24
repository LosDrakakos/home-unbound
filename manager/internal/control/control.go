package control

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Client struct {
	Path    string
	Timeout time.Duration
}

func New(path string) *Client { return &Client{Path: path, Timeout: 3 * time.Second} }
func (c *Client) Command(command string) (string, error) {
	if strings.TrimSpace(command) != command || command == "" || strings.ContainsAny(command, "\r\n\x00") {
		return "", errors.New("invalid control command")
	}
	conn, err := net.DialTimeout("unix", c.Path, c.Timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err = fmt.Fprintf(conn, "UBCT1 %s\n", command); err != nil {
		return "", err
	}
	b, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		return "", err
	}
	out := string(b)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(out)), "error") {
		return out, errors.New(strings.TrimSpace(out))
	}
	return out, nil
}
func (c *Client) Reload() error {
	if _, err := c.Command("reload_keep_cache"); err != nil {
		_, err = c.Command("reload")
		return err
	}
	return nil
}

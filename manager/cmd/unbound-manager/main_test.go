package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unbound-manager/internal/dnsclient"
)

type fakeCommander struct {
	command  string
	response string
	err      error
}

func (f *fakeCommander) Command(command string) (string, error) {
	f.command = command
	return f.response, f.err
}

func TestRunControlCommandJoinsArguments(t *testing.T) {
	fake := &fakeCommander{response: "ok\n"}
	var stdout strings.Builder
	if err := runControlCommand([]string{"flush_zone", "example."}, fake, &stdout); err != nil {
		t.Fatalf("runControlCommand: %v", err)
	}
	if fake.command != "flush_zone example." {
		t.Fatalf("command = %q, want %q", fake.command, "flush_zone example.")
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "ok\\n")
	}
}

func TestRunControlCommandRejectsMissingCommand(t *testing.T) {
	err := runControlCommand(nil, &fakeCommander{}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "command required") {
		t.Fatalf("error = %v, want command-required error", err)
	}
}

func TestRunControlCommandReturnsControlError(t *testing.T) {
	want := errors.New("control failed")
	err := runControlCommand([]string{"status"}, &fakeCommander{err: want}, &strings.Builder{})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want wrapped %v", err, want)
	}
}

func TestShowPasswordReadsGeneratedPassword(t *testing.T) {
	t.Setenv("UI_PASSWORD", "")
	t.Setenv("UI_PASSWORD_FILE", "")
	data := t.TempDir()
	path := filepath.Join(data, "manager", "ui-password")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("generated-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if err := showPassword(paths{data: data}, &stdout, &stderr); err != nil {
		t.Fatalf("showPassword: %v", err)
	}
	if stdout.String() != "generated-secret\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestShowPasswordDoesNotPrintConfiguredSecrets(t *testing.T) {
	for _, test := range []struct {
		name, variable, value string
	}{
		{name: "environment password", variable: "UI_PASSWORD", value: "configured-secret"},
		{name: "password file", variable: "UI_PASSWORD_FILE", value: "/run/secrets/ui-password"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("UI_PASSWORD", "")
			t.Setenv("UI_PASSWORD_FILE", "")
			t.Setenv(test.variable, test.value)
			var stdout, stderr strings.Builder
			if err := showPassword(paths{data: t.TempDir()}, &stdout, &stderr); err != nil {
				t.Fatalf("showPassword: %v", err)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.variable) || strings.Contains(stderr.String(), test.value) {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestShowPasswordErrorsWhenGeneratedPasswordIsMissing(t *testing.T) {
	t.Setenv("UI_PASSWORD", "")
	t.Setenv("UI_PASSWORD_FILE", "")
	err := showPassword(paths{data: t.TempDir()}, &strings.Builder{}, &strings.Builder{})
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error=%v, want missing-file error", err)
	}
}

func TestValidateHealthDNS(t *testing.T) {
	good := dnsclient.Result{RCode: 0, Answers: []dnsclient.Answer{{Name: "localhost.", Type: "A", Value: "127.0.0.1"}}}
	if err := validateHealthDNS(good); err != nil {
		t.Fatalf("good localhost answer rejected: %v", err)
	}
	for _, bad := range []dnsclient.Result{
		{RCode: 2},
		{RCode: 0},
		{RCode: 0, Answers: []dnsclient.Answer{{Name: "localhost.", Type: "A", Value: "127.0.0.2"}}},
	} {
		if err := validateHealthDNS(bad); err == nil {
			t.Fatalf("bad result accepted: %+v", bad)
		}
	}
}

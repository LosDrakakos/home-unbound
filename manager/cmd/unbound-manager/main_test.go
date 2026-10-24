package main

import (
	"errors"
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

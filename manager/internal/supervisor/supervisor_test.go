package supervisor

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRunStopsChildOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := New(func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "sleep")
		c.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		return c
	})
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not stop")
	}
}

func TestCrashLoopFails(t *testing.T) {
	s := New(func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "crash")
		c.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		return c
	})
	s.MaxCrashes = 2
	s.Backoff = 5 * time.Millisecond
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("expected crash loop error")
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" { // New adds this environment.
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "sleep" {
		time.Sleep(time.Hour)
	}
	os.Exit(3)
}

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type Supervisor struct {
	Command     func() *exec.Cmd
	MaxCrashes  int
	Backoff     time.Duration
	CrashWindow time.Duration
}

func New(command func() *exec.Cmd) *Supervisor {
	return &Supervisor{Command: command, MaxCrashes: 5, Backoff: time.Second, CrashWindow: 30 * time.Second}
}
func (s *Supervisor) Run(ctx context.Context) error {
	crashes := 0
	for {
		cmd := s.Command()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		start := time.Now()
		if err := cmd.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			return nil
		case err := <-done:
			if ctx.Err() != nil {
				return nil
			}
			if time.Since(start) > s.CrashWindow {
				crashes = 0
			}
			crashes++
			if crashes >= s.MaxCrashes {
				return fmt.Errorf("unbound crash loop after %d exits: %w", crashes, err)
			}
			timer := time.NewTimer(s.Backoff * time.Duration(crashes))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}

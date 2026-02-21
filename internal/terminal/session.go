package terminal

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
)

// PTYSession manages a single pseudo-terminal session.
type PTYSession struct {
	ID        string
	ptmx      *os.File
	cmd       *exec.Cmd
	LastInput time.Time
	cols      uint16
	rows      uint16
	onOutput  func(sessionID, data string)
	onError   func(sessionID, errMsg string)
	done      chan struct{}
	closeOnce sync.Once
}

// NewPTYSession spawns a new shell and starts relaying output.
func NewPTYSession(id string, cols, rows int, onOutput func(string, string), onError func(string, string)) (*PTYSession, error) {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		for _, candidate := range []string{"/bin/bash", "/bin/sh"} {
			if _, err := os.Stat(candidate); err == nil {
				shell = candidate
				break
			}
		}
		if shell == "" {
			shell = "/bin/sh"
		}
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start pty: %w", err)
	}

	s := &PTYSession{
		ID:        id,
		ptmx:      ptmx,
		cmd:       cmd,
		LastInput: time.Now(),
		cols:      uint16(cols),
		rows:      uint16(rows),
		onOutput:  onOutput,
		onError:   onError,
		done:      make(chan struct{}),
	}

	go s.readLoop()
	return s, nil
}

// Write sends data to the PTY stdin.
func (s *PTYSession) Write(data []byte) error {
	s.LastInput = time.Now()
	_, err := s.ptmx.Write(data)
	return err
}

// Resize changes the PTY window size.
func (s *PTYSession) Resize(cols, rows int) error {
	s.cols = uint16(cols)
	s.rows = uint16(rows)
	return pty.Setsize(s.ptmx, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
}

// Close terminates the PTY session.
func (s *PTYSession) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		_ = s.ptmx.Close()
		_ = s.cmd.Wait()
	})
}

// Done returns a channel that closes when the session ends.
func (s *PTYSession) Done() <-chan struct{} {
	return s.done
}

func (s *PTYSession) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.onOutput(s.ID, string(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				select {
				case <-s.done:
					// Already closing, don't send error
				default:
					s.onError(s.ID, fmt.Sprintf("pty read error: %v", err))
				}
			}
			s.Close()
			return
		}
	}
}

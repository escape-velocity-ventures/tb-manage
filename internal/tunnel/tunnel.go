// Package tunnel provides SSH port forwarding for remote access protocols.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Tunnel holds an active SSH port forward.
type Tunnel struct {
	// LocalAddr is the address the tunnel is listening on (e.g., "127.0.0.1:52341").
	LocalAddr string

	client   *ssh.Client
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// Open establishes an SSH connection and creates a local port forward.
// localPort of 0 picks a random available port.
// remoteAddr is the destination on the remote host (e.g., "127.0.0.1:3389").
func Open(sshAddr string, config *ssh.ClientConfig, localPort int, remoteAddr string) (*Tunnel, error) {
	client, err := ssh.Dial("tcp", sshAddr, config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", sshAddr, err)
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Tunnel{
		LocalAddr: listener.Addr().String(),
		client:    client,
		listener:  listener,
		cancel:    cancel,
	}

	t.wg.Add(1)
	go t.acceptLoop(ctx, remoteAddr)

	return t, nil
}

func (t *Tunnel) acceptLoop(ctx context.Context, remoteAddr string) {
	defer t.wg.Done()

	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("tunnel accept error", "error", err)
				return
			}
		}

		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.forward(ctx, conn, remoteAddr)
		}()
	}
}

func (t *Tunnel) forward(ctx context.Context, local net.Conn, remoteAddr string) {
	defer local.Close()

	remote, err := t.client.Dial("tcp", remoteAddr)
	if err != nil {
		slog.Warn("tunnel dial remote", "addr", remoteAddr, "error", err)
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(remote, local)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, remote)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Close shuts down the tunnel, closing the listener and SSH connection.
func (t *Tunnel) Close() error {
	t.cancel()
	t.listener.Close()
	err := t.client.Close()
	t.wg.Wait()
	return err
}

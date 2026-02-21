package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tinkerbelle-io/tb-discover/internal/protocol"
	"github.com/tinkerbelle-io/tb-discover/internal/terminal"
)

// nodeHostname returns the Kubernetes node name (NODE_NAME env) if set,
// falling back to os.Hostname() for non-k8s environments.
func nodeHostname() string {
	if n := os.Getenv("NODE_NAME"); n != "" {
		return n
	}
	h, _ := os.Hostname()
	return h
}

// Agent manages the WebSocket connection, terminal sessions, and scan loop.
type Agent struct {
	conn        *websocket.Conn
	sessions    map[string]*terminal.PTYSession
	mu          sync.RWMutex
	idleTimeout time.Duration
	clusterID   string
	agentID     string
	wsURL       string
	token       string
	writeMu     sync.Mutex

	// Permissions
	permissions  map[string]bool
	maxSessions  int
	shellCommand []string

	// Scan loop
	scanLoop *ScanLoop
	log      *slog.Logger
}

const (
	// DefaultMaxSessions is the maximum concurrent terminal sessions per agent.
	DefaultMaxSessions = 10
)

// Config holds agent configuration.
type Config struct {
	WSURL        string
	Token        string
	ClusterID    string
	IdleTimeout  time.Duration
	ScanConfig   *ScanLoopConfig // nil = no scan loop
	Permissions  []string        // e.g., ["terminal", "scan"]
	MaxSessions  int             // 0 = DefaultMaxSessions
	ShellCommand []string        // Custom shell command (e.g., ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--", "/bin/bash"])
}

// New creates a new Agent (does not connect yet).
func New(cfg Config) *Agent {
	hostname := nodeHostname()
	logger := slog.Default().With("component", "agent", "host", hostname)

	perms := make(map[string]bool)
	for _, p := range cfg.Permissions {
		perms[p] = true
	}

	maxSessions := cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}

	a := &Agent{
		sessions:     make(map[string]*terminal.PTYSession),
		idleTimeout:  cfg.IdleTimeout,
		clusterID:    cfg.ClusterID,
		agentID:      hostname,
		wsURL:        cfg.WSURL,
		token:        cfg.Token,
		permissions:  perms,
		maxSessions:  maxSessions,
		shellCommand: cfg.ShellCommand,
		log:          logger,
	}

	if cfg.ScanConfig != nil {
		a.scanLoop = NewScanLoop(*cfg.ScanConfig, logger)
	}

	return a
}

// Run connects to the gateway and processes messages until interrupted.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-sigCh:
			a.log.Info("received shutdown signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	// Start scan loop if configured
	if a.scanLoop != nil {
		go a.scanLoop.Run(ctx)
	}

	// If no WebSocket URL, run scan-only mode
	if a.wsURL == "" {
		a.log.Info("no WebSocket URL configured, running in scan-only mode")
		<-ctx.Done()
		return nil
	}

	if err := a.connect(); err != nil {
		return fmt.Errorf("initial connection failed: %w", err)
	}
	defer a.shutdown()

	a.log.Info("connected to gateway", "url", a.wsURL)

	// Send immediate heartbeat so gateway knows our agentId
	a.sendMessage(protocol.HeartbeatMessage{
		Type:      protocol.TypeHeartbeat,
		AgentID:   a.agentID,
		ClusterID: a.clusterID,
		Timestamp: time.Now().Unix(),
	})

	// Start periodic heartbeat
	go a.heartbeatLoop(ctx)

	// Start idle checker
	go a.idleCheckLoop(ctx)

	// Message read loop
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_, msg, err := a.conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.log.Warn("websocket read error, reconnecting", "error", err)
			if err := a.reconnect(ctx); err != nil {
				return fmt.Errorf("reconnect failed: %w", err)
			}
			continue
		}

		if err := a.handleMessage(msg); err != nil {
			a.log.Error("message handling failed", "error", err)
		}
	}
}

func (a *Agent) connect() error {
	u, err := url.Parse(a.wsURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("token", a.token)
	u.RawQuery = q.Encode()

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	a.conn = conn
	return nil
}

func (a *Agent) reconnect(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		a.log.Info("attempting reconnect", "backoff", backoff)
		if err := a.connect(); err != nil {
			a.log.Warn("reconnect failed", "error", err, "backoff", backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		a.log.Info("reconnected to gateway")
		return nil
	}
}

func (a *Agent) shutdown() {
	a.mu.Lock()
	for id, s := range a.sessions {
		a.log.Info("closing session", "session_id", id)
		s.Close()
	}
	a.sessions = make(map[string]*terminal.PTYSession)
	a.mu.Unlock()

	if a.conn != nil {
		_ = a.conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		_ = a.conn.Close()
	}
}

func (a *Agent) handleMessage(raw []byte) error {
	var env protocol.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}

	switch env.Type {
	case protocol.TypeSessionOpen:
		var msg protocol.SessionOpenMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		return a.handleSessionOpen(msg)

	case protocol.TypePTYInput:
		var msg protocol.PTYInputMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		return a.handlePTYInput(msg)

	case protocol.TypePTYResize:
		var msg protocol.PTYResizeMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		return a.handlePTYResize(msg)

	case protocol.TypeSessionClose:
		var msg protocol.SessionCloseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		return a.handleSessionClose(msg)

	default:
		a.log.Debug("unknown message type", "type", env.Type)
		return nil
	}
}

// buildShellCommand builds the shell command to execute based on the target.
// Returns the command args and an error code if the target is invalid.
func (a *Agent) buildShellCommand(target *protocol.TerminalTarget) ([]string, string, error) {
	if target == nil {
		return a.shellCommand, "", nil
	}

	shell := target.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	switch target.Type {
	case "host":
		// Use agent's configured shell or the target's shell override
		if target.Shell != "" {
			return []string{target.Shell}, "", nil
		}
		return a.shellCommand, "", nil

	case "lima":
		if target.Name == "" {
			return nil, "TARGET_NOT_FOUND", fmt.Errorf("lima target requires a VM name")
		}
		cmd := []string{"limactl", "shell", target.Name}
		if target.Shell != "" {
			cmd = append(cmd, target.Shell)
		}
		return cmd, "", nil

	case "docker":
		if target.Container == "" {
			return nil, "TARGET_NOT_FOUND", fmt.Errorf("docker target requires a container name")
		}
		runtime := target.Runtime
		if runtime == "" {
			runtime = "docker"
		}
		return []string{runtime, "exec", "-it", target.Container, shell}, "", nil

	case "k8s-pod":
		if target.Pod == "" || target.Namespace == "" {
			return nil, "TARGET_NOT_FOUND", fmt.Errorf("k8s-pod target requires pod and namespace")
		}
		cmd := []string{"kubectl", "exec", "-it", target.Pod, "-n", target.Namespace}
		if target.Container != "" {
			cmd = append(cmd, "-c", target.Container)
		}
		cmd = append(cmd, "--", shell)
		return cmd, "", nil

	default:
		return nil, "UNSUPPORTED_TARGET", fmt.Errorf("unsupported target type: %s", target.Type)
	}
}

func (a *Agent) handleSessionOpen(msg protocol.SessionOpenMessage) error {
	// Permission check
	if !a.permissions["terminal"] {
		a.sendMessage(protocol.SessionErrorMessage{
			Type:      protocol.TypeSessionError,
			SessionID: msg.SessionID,
			Error:     "terminal permission not granted",
			Code:      "PERMISSION_DENIED",
		})
		return fmt.Errorf("terminal permission not granted")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.sessions[msg.SessionID]; exists {
		return fmt.Errorf("session %s already exists", msg.SessionID)
	}

	// Session limit check
	if len(a.sessions) >= a.maxSessions {
		a.sendMessage(protocol.SessionErrorMessage{
			Type:      protocol.TypeSessionError,
			SessionID: msg.SessionID,
			Error:     fmt.Sprintf("max sessions reached (%d)", a.maxSessions),
		})
		return fmt.Errorf("max sessions reached (%d)", a.maxSessions)
	}

	// Build command based on target type
	shellCmd, errCode, err := a.buildShellCommand(msg.Target)
	if err != nil {
		a.sendMessage(protocol.SessionErrorMessage{
			Type:      protocol.TypeSessionError,
			SessionID: msg.SessionID,
			Error:     err.Error(),
			Code:      errCode,
		})
		return err
	}

	targetDesc := "host"
	if msg.Target != nil {
		targetDesc = msg.Target.Type
	}

	session, err := terminal.NewPTYSession(
		msg.SessionID,
		msg.Cols,
		msg.Rows,
		shellCmd,
		func(sessionID, data string) {
			a.sendMessage(protocol.PTYOutputMessage{
				Type:      protocol.TypePTYOutput,
				SessionID: sessionID,
				Data:      data,
			})
		},
		func(sessionID, errMsg string) {
			a.sendMessage(protocol.SessionErrorMessage{
				Type:      protocol.TypeSessionError,
				SessionID: sessionID,
				Error:     errMsg,
			})
		},
	)
	if err != nil {
		a.sendMessage(protocol.SessionErrorMessage{
			Type:      protocol.TypeSessionError,
			SessionID: msg.SessionID,
			Error:     fmt.Sprintf("failed to create session: %v", err),
			Code:      "INTERNAL_ERROR",
		})
		return err
	}

	a.sessions[msg.SessionID] = session
	a.log.Info("session opened", "session_id", msg.SessionID, "target", targetDesc)

	// Watch for session exit
	go func() {
		<-session.Done()
		a.mu.Lock()
		delete(a.sessions, msg.SessionID)
		a.mu.Unlock()
		a.sendMessage(protocol.SessionCloseMessage{
			Type:      protocol.TypeSessionClose,
			SessionID: msg.SessionID,
		})
		a.log.Info("session ended", "session_id", msg.SessionID)
	}()

	a.sendMessage(protocol.SessionReadyMessage{
		Type:      protocol.TypeSessionReady,
		SessionID: msg.SessionID,
	})

	return nil
}

func (a *Agent) handlePTYInput(msg protocol.PTYInputMessage) error {
	a.mu.RLock()
	session, ok := a.sessions[msg.SessionID]
	a.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %s not found", msg.SessionID)
	}
	return session.Write([]byte(msg.Data))
}

func (a *Agent) handlePTYResize(msg protocol.PTYResizeMessage) error {
	a.mu.RLock()
	session, ok := a.sessions[msg.SessionID]
	a.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %s not found", msg.SessionID)
	}
	return session.Resize(msg.Cols, msg.Rows)
}

func (a *Agent) handleSessionClose(msg protocol.SessionCloseMessage) error {
	a.mu.Lock()
	session, ok := a.sessions[msg.SessionID]
	if ok {
		delete(a.sessions, msg.SessionID)
	}
	a.mu.Unlock()
	if ok {
		session.Close()
		a.log.Info("session closed", "session_id", msg.SessionID)
	}
	return nil
}

func (a *Agent) sendMessage(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		a.log.Error("failed to marshal message", "error", err)
		return
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.conn == nil {
		a.log.Warn("no websocket connection, dropping message")
		return
	}
	if err := a.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		a.log.Error("failed to send message", "error", err)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendMessage(protocol.HeartbeatMessage{
				Type:      protocol.TypeHeartbeat,
				AgentID:   a.agentID,
				ClusterID: a.clusterID,
				Timestamp: time.Now().Unix(),
			})
		}
	}
}

func (a *Agent) idleCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkIdleSessions()
		}
	}
}

func (a *Agent) checkIdleSessions() {
	a.mu.RLock()
	var expired []string
	for id, s := range a.sessions {
		if time.Since(s.LastInput) > a.idleTimeout {
			expired = append(expired, id)
		}
	}
	a.mu.RUnlock()

	for _, id := range expired {
		a.mu.Lock()
		session, ok := a.sessions[id]
		if ok {
			delete(a.sessions, id)
		}
		a.mu.Unlock()
		if ok {
			a.sendMessage(protocol.SessionErrorMessage{
				Type:      protocol.TypeSessionError,
				SessionID: id,
				Error:     "idle timeout",
			})
			session.Close()
			a.log.Info("session closed due to idle timeout", "session_id", id)
		}
	}
}

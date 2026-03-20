package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tinkerbelle-io/tb-manage/internal/audit"
	"github.com/tinkerbelle-io/tb-manage/internal/auth"
	"github.com/tinkerbelle-io/tb-manage/internal/signing"
	"github.com/tinkerbelle-io/tb-manage/internal/protocol"
	"github.com/tinkerbelle-io/tb-manage/internal/terminal"
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
	token              string
	tokenInURLFallback bool
	identityMode       string
	hostIdentity       *auth.HostIdentity
	writeMu     sync.Mutex

	// Permissions
	permissions  map[string]bool
	maxSessions  int
	shellCommand []string

	// Persistent sessions (tmux)
	tmuxEnabled bool

	// Audit
	auditLog *audit.AuditLogger

	// Signing verification
	verifier *signing.Verifier

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
	ShellCommand       []string // Custom shell command (e.g., ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--", "/bin/bash"])
	TokenInURLFallback bool     // DEPRECATED: also send token in URL query param for migration
	AuditLogPath       string   // Custom audit log path (empty = default)
	PublicKey          string   // Ed25519 public key for command verification (hex or base64)
	IdentityMode       string            // "token" or "ssh-host-key"
	HostIdentity       *auth.HostIdentity // SSH host key identity (when IdentityMode == "ssh-host-key")
	DisableTmux        bool               // Disable persistent terminal sessions (no tmux)
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

	// Initialize audit logger
	var auditLog *audit.AuditLogger
	if al, err := audit.NewAuditLogger(cfg.AuditLogPath); err != nil {
		logger.Warn("failed to initialize audit logger", "error", err)
	} else {
		auditLog = al
		logger.Info("audit logging enabled", "path", cfg.AuditLogPath)
	}

	// Initialize signature verifier if public key provided
	var verifier *signing.Verifier
	if cfg.PublicKey != "" {
		pubKey, err := signing.ParsePublicKey(cfg.PublicKey)
		if err != nil {
			logger.Error("invalid public key", "error", err)
			return nil
		}
		verifier = signing.NewVerifier(pubKey)
		logger.Info("command signature verification enabled")
	} else {
		logger.Warn("no public key configured — commands will NOT be verified (insecure)")
	}

	// Check tmux availability for persistent sessions
	tmuxEnabled := !cfg.DisableTmux && terminal.TmuxAvailable()
	if tmuxEnabled {
		logger.Info("persistent terminal sessions enabled (tmux)")
	} else if cfg.DisableTmux {
		logger.Info("persistent terminal sessions disabled (--no-tmux)")
	} else {
		logger.Info("persistent terminal sessions unavailable (tmux not found)")
	}

	a := &Agent{
		sessions:     make(map[string]*terminal.PTYSession),
		idleTimeout:  cfg.IdleTimeout,
		clusterID:    cfg.ClusterID,
		agentID:      hostname,
		wsURL:        cfg.WSURL,
		token:              cfg.Token,
		tokenInURLFallback: cfg.TokenInURLFallback,
		identityMode:       cfg.IdentityMode,
		hostIdentity:       cfg.HostIdentity,
		permissions:  perms,
		maxSessions:  maxSessions,
		shellCommand: cfg.ShellCommand,
		tmuxEnabled:  tmuxEnabled,
		log:          logger,
		auditLog:     auditLog,
		verifier:     verifier,
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
	var initialSessions []string
	if a.tmuxEnabled {
		initialSessions = terminal.ListTmuxSessions()
	}
	a.sendMessage(protocol.HeartbeatMessage{
		Type:      protocol.TypeHeartbeat,
		AgentID:   a.agentID,
		ClusterID: a.clusterID,
		Timestamp: time.Now().Unix(),
		Sessions:  initialSessions,
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

	headers := http.Header{}

	if a.identityMode == "ssh-host-key" && a.hostIdentity != nil {
		// SSH host key auth: sign fingerprint:timestamp:nonce and send in headers
		// (not query params — signatures in URLs leak to logs and proxy caches)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}
		nonce := hex.EncodeToString(nonceBytes)
		// Domain-separated signing: prefix prevents cross-protocol signature abuse
		message := "tb-manage:ws:v1:" + a.hostIdentity.Fingerprint + ":" + ts + ":" + nonce
		sig := a.hostIdentity.SignRequest([]byte(message))

		headers.Set("X-TB-Key-Fingerprint", a.hostIdentity.Fingerprint)
		headers.Set("X-TB-Timestamp", ts)
		headers.Set("X-TB-Nonce", nonce)
		headers.Set("X-TB-Signature", sig)

		a.log.Info("connecting with ssh-host-key identity", "fingerprint", a.hostIdentity.Fingerprint)
	} else {
		// Token auth (existing path)
		headers.Set("Authorization", "Bearer "+a.token)

		// DEPRECATED: also send token in URL query param for backward compatibility
		if a.tokenInURLFallback {
			a.log.Warn("sending token in URL query parameter is deprecated; set token_in_url_fallback: false once gateway supports Authorization header")
			q := u.Query()
			q.Set("token", a.token)
			u.RawQuery = q.Encode()
		}
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
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
		a.log.Info("detaching session", "session_id", id)
		s.Close() // Kills PTY viewport; tmux sessions stay alive
	}
	a.sessions = make(map[string]*terminal.PTYSession)
	a.mu.Unlock()

	if a.auditLog != nil {
		a.auditLog.Close()
	}

	if a.conn != nil {
		_ = a.conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		_ = a.conn.Close()
	}
}

func (a *Agent) handleMessage(raw []byte) error {
	// Verify command signature if verifier is configured
	if a.verifier != nil {
		command, result := a.verifier.Verify(raw)
		if !result.Valid {
			a.log.Warn("rejected unsigned/invalid command",
				"reason", result.Reason,
				"user_id", result.UserID,
				"origin", result.Origin,
			)
			if a.auditLog != nil {
				a.auditLog.Log(audit.AuditEntry{
					EventType: audit.EventBlocked,
					UserID:    result.UserID,
					Origin:    result.Origin,
					Reason:    result.Reason,
				})
			}
			return fmt.Errorf("command verification failed: %s", result.Reason)
		}
		// Use the stripped command (without signing fields) for processing
		raw = command
	}

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

	// Validate target fields to prevent shell injection
	if err := protocol.ValidateTerminalTarget(target); err != nil {
		return nil, "INVALID_TARGET", err
	}

	shell := target.Shell
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "powershell.exe"
		} else {
			shell = "/bin/sh"
		}
	}

	switch target.Type {
	case "host":
		if runtime.GOOS == "windows" {
			// Windows host terminals route through SSH to localhost.
			// SSHD is enabled by the installer; the remote side allocates a PTY.
			// TODO: Replace with Windows ConPTY API to eliminate the SSH hop entirely.
			// Using UserKnownHostsFile with a pinned key from installation.
			cmd := []string{"ssh", "-tt",
				"-o", "StrictHostKeyChecking=yes",
				"-o", "UserKnownHostsFile=" + windowsLocalhostKnownHosts(),
				"--", "127.0.0.1"}
			switch {
			case target.Shell != "":
				cmd = append(cmd, target.Shell)
			case len(a.shellCommand) > 0:
				cmd = append(cmd, a.shellCommand...)
			}
			return cmd, "", nil
		}
		// Unix: direct PTY
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

	case "ssh":
		if target.Host == "" {
			return nil, "TARGET_NOT_FOUND", fmt.Errorf("ssh target requires a host")
		}
		cmd := []string{"ssh"}
		if target.Port != 0 {
			cmd = append(cmd, "-p", fmt.Sprintf("%d", target.Port))
		}
		// -o StrictHostKeyChecking=accept-new: accept on first connect, reject changes
		cmd = append(cmd, "-o", "StrictHostKeyChecking=accept-new")
		// Build user@host
		host := target.Host
		if target.User != "" {
			host = target.User + "@" + host
		}
		// Use -- to prevent argument injection via crafted hostnames
		cmd = append(cmd, "--", host)
		return cmd, "", nil

	default:
		return nil, "UNSUPPORTED_TARGET", fmt.Errorf("unsupported target type: %s", target.Type)
	}
}

// windowsLocalhostKnownHosts returns the path to a known_hosts file that
// contains the localhost SSH host key, pinned during tb-manage installation.
// If the file doesn't exist, returns a path that ssh will fail against
// (StrictHostKeyChecking=yes will reject unknown hosts).
func windowsLocalhostKnownHosts() string {
	// The installer creates this file with the local sshd host key.
	dataDir := os.Getenv("PROGRAMDATA")
	if dataDir == "" {
		dataDir = `C:\ProgramData`
	}
	return dataDir + `\tb-manage\localhost_known_hosts`
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

	onOutput := func(sessionID, data string) {
		a.sendMessage(protocol.PTYOutputMessage{
			Type:      protocol.TypePTYOutput,
			SessionID: sessionID,
			Data:      data,
		})
	}
	onError := func(sessionID, errMsg string) {
		a.sendMessage(protocol.SessionErrorMessage{
			Type:      protocol.TypeSessionError,
			SessionID: sessionID,
			Error:     errMsg,
		})
	}

	var session *terminal.PTYSession
	if a.tmuxEnabled {
		if terminal.TmuxSessionExists(msg.SessionID) {
			// Resume: attach to existing tmux session
			cmd := terminal.AttachTmuxCommand(msg.SessionID)
			session, err = terminal.NewPTYSessionWithCmd(msg.SessionID, msg.Cols, msg.Rows, cmd, onOutput, onError)
			if err == nil {
				a.log.Info("session resumed (tmux attach)", "session_id", msg.SessionID, "target", targetDesc)
			}
		} else {
			// New: create tmux session
			cmd := terminal.NewTmuxCommand(msg.SessionID, msg.Cols, msg.Rows, shellCmd)
			session, err = terminal.NewPTYSessionWithCmd(msg.SessionID, msg.Cols, msg.Rows, cmd, onOutput, onError)
			if err == nil {
				a.log.Info("session created (tmux new)", "session_id", msg.SessionID, "target", targetDesc)
			}
		}
	} else {
		session, err = terminal.NewPTYSession(msg.SessionID, msg.Cols, msg.Rows, shellCmd, onOutput, onError)
		if err == nil {
			a.log.Info("session opened", "session_id", msg.SessionID, "target", targetDesc)
		}
	}

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
	if a.auditLog != nil {
		a.auditLog.Log(audit.AuditEntry{
			SessionID: msg.SessionID,
			EventType: audit.EventSessionOpen,
		})
	}

	// Watch for session exit
	go func() {
		<-session.Done()
		a.mu.Lock()
		delete(a.sessions, msg.SessionID)
		a.mu.Unlock()
		if a.auditLog != nil {
			a.auditLog.Log(audit.AuditEntry{
				SessionID: msg.SessionID,
				EventType: audit.EventSessionClose,
			})
		}
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
	if a.auditLog != nil {
		a.auditLog.Log(audit.AuditEntry{
			SessionID: msg.SessionID,
			EventType: audit.EventCommand,
			Input:     msg.Data,
		})
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
		if a.auditLog != nil {
			a.auditLog.Log(audit.AuditEntry{
				SessionID: msg.SessionID,
				EventType: audit.EventSessionClose,
			})
		}
		session.Close()

		// Destroy the persistent tmux session on explicit close
		if a.tmuxEnabled {
			if err := terminal.DestroyTmuxSession(msg.SessionID); err != nil {
				a.log.Debug("tmux session destroy", "session_id", msg.SessionID, "error", err)
			}
		}
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
			var sessions []string
			if a.tmuxEnabled {
				sessions = terminal.ListTmuxSessions()
			}
			a.sendMessage(protocol.HeartbeatMessage{
				Type:      protocol.TypeHeartbeat,
				AgentID:   a.agentID,
				ClusterID: a.clusterID,
				Timestamp: time.Now().Unix(),
				Sessions:  sessions,
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

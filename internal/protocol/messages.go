package protocol

// Message types
const (
	TypeSessionOpen  = "session.open"
	TypeSessionClose = "session.close"
	TypeSessionReady = "session.ready"
	TypeSessionError = "session.error"
	TypePTYInput     = "pty.input"
	TypePTYOutput    = "pty.output"
	TypePTYResize    = "pty.resize"
	TypeHeartbeat    = "agent.heartbeat"
)

// Envelope is used for initial JSON decode to determine message type
type Envelope struct {
	Type string `json:"type"`
}

// TerminalTarget specifies what to connect to within a host.
// Type must be one of: "host", "lima", "docker", "k8s-pod".
type TerminalTarget struct {
	Type      string `json:"type"`                // host | lima | docker | k8s-pod
	Name      string `json:"name,omitempty"`      // lima VM name
	Container string `json:"container,omitempty"` // docker container or k8s container
	Runtime   string `json:"runtime,omitempty"`   // docker | podman
	Pod       string `json:"pod,omitempty"`       // k8s pod name
	Namespace string `json:"namespace,omitempty"` // k8s namespace
	Shell     string `json:"shell,omitempty"`     // override shell
}

type SessionOpenMessage struct {
	Type      string          `json:"type"`
	SessionID string          `json:"sessionId"`
	HostID    string          `json:"hostId"`
	ClusterID string          `json:"clusterId"`
	Cols      int             `json:"cols,omitempty"`
	Rows      int             `json:"rows,omitempty"`
	Target    *TerminalTarget `json:"target,omitempty"`
}

type SessionCloseMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
}

type SessionReadyMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
}

type SessionErrorMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
}

type PTYInputMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Data      string `json:"data"`
}

type PTYOutputMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Data      string `json:"data"`
}

type PTYResizeMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

type HeartbeatMessage struct {
	Type      string `json:"type"`
	AgentID   string `json:"agentId"`
	ClusterID string `json:"clusterId"`
	Timestamp int64  `json:"timestamp"`
}

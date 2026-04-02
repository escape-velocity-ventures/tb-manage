// Package reconciler provides coordination for rolling restarts across cluster nodes.
// It uses a Kubernetes ConfigMap as a distributed lock to prevent multiple simultaneous
// service restarts, maintaining quorum for critical services like k3s.
package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// staleLockThreshold is how long a "restarting" state can persist before
	// being considered stale and eligible for automatic cleanup.
	staleLockThreshold = 5 * time.Minute
)

// RestartState represents the restart status of a single node, stored as JSON
// in the coordination ConfigMap.
type RestartState struct {
	NodeName  string    `json:"nodeName"`
	Status    string    `json:"status"` // "restarting", "healthy", "failed"
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
}

// RestartCoordinator coordinates rolling restarts across nodes using a shared
// ConfigMap to prevent more than maxConcurrent simultaneous restarts.
type RestartCoordinator struct {
	client        kubernetes.Interface
	namespace     string
	configMapName string
	nodeName      string
	maxConcurrent int
}

// execCmd is the interface for command execution, enabling test mocking.
type execCmd interface {
	CombinedOutput() ([]byte, error)
}

// execCommand is the function used to create commands. Override in tests.
var execCommand = func(name string, args ...string) execCmd {
	return exec.Command(name, args...)
}

// NewRestartCoordinator creates a coordinator for the given node.
func NewRestartCoordinator(client kubernetes.Interface, namespace, nodeName string, maxConcurrent int) *RestartCoordinator {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &RestartCoordinator{
		client:        client,
		namespace:     namespace,
		configMapName: "tb-manage-restart-state",
		nodeName:      nodeName,
		maxConcurrent: maxConcurrent,
	}
}

// AcquireLock attempts to claim a restart slot for this node. Returns true if
// this node can proceed with the restart. If maxConcurrent nodes are already
// restarting, returns false (caller should retry later). Stale locks (timestamp
// older than 5 minutes) are automatically cleaned up.
func (rc *RestartCoordinator) AcquireLock(ctx context.Context, service string) (bool, error) {
	cm, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(ctx, rc.configMapName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		// ConfigMap doesn't exist yet -- create it with our state.
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rc.configMapName,
				Namespace: rc.namespace,
			},
			Data: map[string]string{},
		}
		rc.setNodeState(cm, service, "restarting")
		_, createErr := rc.client.CoreV1().ConfigMaps(rc.namespace).Create(ctx, cm, metav1.CreateOptions{})
		if createErr != nil {
			return false, fmt.Errorf("failed to create restart-state configmap: %w", createErr)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get restart-state configmap: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	// Clean stale locks and count active restarts.
	now := time.Now()
	activeRestarts := 0
	for nodeName, raw := range cm.Data {
		var state RestartState
		if unmarshalErr := json.Unmarshal([]byte(raw), &state); unmarshalErr != nil {
			log.Printf("restart-coordinator: removing malformed entry for %s", nodeName)
			delete(cm.Data, nodeName)
			continue
		}

		if state.Status != "restarting" {
			continue
		}

		// Check for stale lock.
		if now.Sub(state.Timestamp) > staleLockThreshold {
			log.Printf("restart-coordinator: stale restart lock for node %s (%s old), clearing",
				nodeName, now.Sub(state.Timestamp).Round(time.Second))
			delete(cm.Data, nodeName)
			continue
		}

		// This node's own existing lock doesn't count against it (idempotent re-acquire).
		if nodeName == rc.nodeName {
			continue
		}

		activeRestarts++
	}

	if activeRestarts >= rc.maxConcurrent {
		// Persist any stale lock cleanups even if we can't acquire.
		_, _ = rc.client.CoreV1().ConfigMaps(rc.namespace).Update(ctx, cm, metav1.UpdateOptions{})
		return false, nil
	}

	// Write our restart intent.
	rc.setNodeState(cm, service, "restarting")
	_, err = rc.client.CoreV1().ConfigMaps(rc.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to update restart-state configmap: %w", err)
	}
	return true, nil
}

// ReleaseLock marks this node's restart as complete. The status parameter
// should be "healthy" on success or "failed" if the restart did not succeed.
func (rc *RestartCoordinator) ReleaseLock(ctx context.Context, status string) error {
	cm, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(ctx, rc.configMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get restart-state configmap: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	// Update this node's status, preserving the service field if present.
	raw, exists := cm.Data[rc.nodeName]
	if !exists {
		rc.setNodeState(cm, "", status)
	} else {
		var state RestartState
		if unmarshalErr := json.Unmarshal([]byte(raw), &state); unmarshalErr != nil {
			rc.setNodeState(cm, "", status)
		} else {
			state.Status = status
			state.Timestamp = time.Now()
			b, _ := json.Marshal(state)
			cm.Data[rc.nodeName] = string(b)
		}
	}

	_, err = rc.client.CoreV1().ConfigMaps(rc.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update restart-state configmap: %w", err)
	}
	return nil
}

// RestartService executes a service restart via nsenter into the host PID namespace.
// Uses: nsenter -t 1 -m -- systemctl restart <service>
// This assumes the pod has hostPID: true and appropriate capabilities.
func RestartService(service string) error {
	cmd := execCommand("nsenter", "-t", "1", "-m", "--", "systemctl", "restart", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart %s: %w (output: %s)", service, err, string(output))
	}
	return nil
}

// WaitForHealth polls until the service is healthy or the timeout is reached.
// For k3s, this checks the Kubernetes node's Ready condition. Returns nil if
// healthy, error if timeout (circuit breaker).
func (rc *RestartCoordinator) WaitForHealth(ctx context.Context, service string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled waiting for %s health on %s: %w",
				service, rc.nodeName, ctx.Err())
		case <-deadline:
			return fmt.Errorf("timeout waiting for %s to become healthy on %s (circuit breaker after %s)",
				service, rc.nodeName, timeout)
		case <-ticker.C:
			healthy, checkErr := rc.isNodeReady(ctx)
			if checkErr != nil {
				continue
			}
			if healthy {
				return nil
			}
		}
	}
}

// setNodeState writes a RestartState for this node into the ConfigMap data map.
func (rc *RestartCoordinator) setNodeState(cm *corev1.ConfigMap, service, status string) {
	state := RestartState{
		NodeName:  rc.nodeName,
		Status:    status,
		Timestamp: time.Now(),
		Service:   service,
	}
	b, _ := json.Marshal(state)
	cm.Data[rc.nodeName] = string(b)
}

// isNodeReady checks if this node has the Ready condition set to True.
func (rc *RestartCoordinator) isNodeReady(ctx context.Context) (bool, error) {
	node, err := rc.client.CoreV1().Nodes().Get(ctx, rc.nodeName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue, nil
		}
	}
	return false, nil
}

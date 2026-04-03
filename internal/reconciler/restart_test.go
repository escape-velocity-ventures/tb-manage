package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// helper: create a RestartCoordinator with fake client and defaults.
func newTestCoordinator(t *testing.T, nodeName string, maxConcurrent int, objects ...metav1.Object) *RestartCoordinator {
	t.Helper()
	var runtimeObjects []interface{ GetObjectKind() interface{ GroupVersionKind() interface{} } }
	// Convert to runtime.Object for fake clientset
	clientset := fake.NewSimpleClientset()
	// Pre-create any ConfigMaps we need
	for _, obj := range objects {
		if cm, ok := obj.(*corev1.ConfigMap); ok {
			_, err := clientset.CoreV1().ConfigMaps(cm.Namespace).Create(context.Background(), cm, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create configmap: %v", err)
			}
		}
	}
	_ = runtimeObjects
	rc := NewRestartCoordinator(clientset, "infrastructure", nodeName, maxConcurrent)
	return rc
}

// helper: create the restart-state ConfigMap with given states.
func makeRestartStateCM(states map[string]RestartState) *corev1.ConfigMap {
	data := make(map[string]string)
	for k, v := range states {
		b, _ := json.Marshal(v)
		data[k] = string(b)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tb-manage-restart-state",
			Namespace: "infrastructure",
		},
		Data: data,
	}
}

func TestAcquireLock_NoOtherRestarts(t *testing.T) {
	// When no other nodes are restarting, AcquireLock should succeed.
	rc := newTestCoordinator(t, "plato-k3s", 1)

	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock to be acquired when no other restarts in progress")
	}

	// Verify the ConfigMap was created with our node's state.
	cm, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(context.Background(), rc.configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected configmap to exist: %v", err)
	}
	var state RestartState
	if err := json.Unmarshal([]byte(cm.Data["plato-k3s"]), &state); err != nil {
		t.Fatalf("failed to unmarshal state: %v", err)
	}
	if state.Status != "restarting" {
		t.Errorf("expected status 'restarting', got %q", state.Status)
	}
	if state.Service != "k3s" {
		t.Errorf("expected service 'k3s', got %q", state.Service)
	}
}

func TestAcquireLock_FailsWhenMaxConcurrentReached(t *testing.T) {
	// When maxConcurrent=1 and another node is already restarting, should fail.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)
	rc := newTestCoordinator(t, "plato-k3s", 1, cm)

	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquired {
		t.Fatal("expected lock NOT to be acquired when maxConcurrent=1 and 1 node already restarting")
	}
}

func TestAcquireLock_SucceedsAfterStaleLockCleanup(t *testing.T) {
	// A stale lock (>5 min) should be cleaned up, allowing new lock.
	staleTime := time.Now().Add(-6 * time.Minute) // 6 minutes ago = stale
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: staleTime,
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)
	rc := newTestCoordinator(t, "plato-k3s", 1, cm)

	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock to be acquired after stale lock cleanup")
	}

	// Verify stale entry was cleaned up.
	updatedCM, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(context.Background(), rc.configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get configmap: %v", err)
	}
	if _, exists := updatedCM.Data["aristotle-k3s"]; exists {
		var staleState RestartState
		json.Unmarshal([]byte(updatedCM.Data["aristotle-k3s"]), &staleState)
		if staleState.Status == "restarting" {
			t.Error("expected stale lock for aristotle-k3s to be cleaned up")
		}
	}
}

func TestAcquireLock_NonStaleBlocksLock(t *testing.T) {
	// A lock that's 4 minutes old (under 5 min threshold) should still block.
	recentTime := time.Now().Add(-4 * time.Minute)
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: recentTime,
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)
	rc := newTestCoordinator(t, "plato-k3s", 1, cm)

	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquired {
		t.Fatal("expected lock NOT to be acquired when recent (non-stale) restart in progress")
	}
}

func TestReleaseLock_Healthy(t *testing.T) {
	// After acquiring a lock, ReleaseLock should set status to "healthy".
	rc := newTestCoordinator(t, "plato-k3s", 1)

	// First acquire
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil || !acquired {
		t.Fatalf("setup: failed to acquire lock: acquired=%v err=%v", acquired, err)
	}

	// Release as healthy
	if err := rc.ReleaseLock(context.Background(), "healthy"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cm, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(context.Background(), rc.configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get configmap: %v", err)
	}
	var state RestartState
	if err := json.Unmarshal([]byte(cm.Data["plato-k3s"]), &state); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if state.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %q", state.Status)
	}
}

func TestReleaseLock_Failed(t *testing.T) {
	// ReleaseLock with "failed" should set status to "failed".
	rc := newTestCoordinator(t, "plato-k3s", 1)

	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil || !acquired {
		t.Fatalf("setup: failed to acquire lock: acquired=%v err=%v", acquired, err)
	}

	if err := rc.ReleaseLock(context.Background(), "failed"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cm, err := rc.client.CoreV1().ConfigMaps(rc.namespace).Get(context.Background(), rc.configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get configmap: %v", err)
	}
	var state RestartState
	if err := json.Unmarshal([]byte(cm.Data["plato-k3s"]), &state); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if state.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", state.Status)
	}
}

func TestRestartService_CallsNsenter(t *testing.T) {
	// RestartService should call nsenter with the correct args.
	var capturedName string
	var capturedArgs []string
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(name string, args ...string) execCmd {
		capturedName = name
		capturedArgs = args
		return &fakeCmd{output: []byte(""), err: nil}
	}

	err := RestartService("k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedName != "nsenter" {
		t.Errorf("expected command 'nsenter', got %q", capturedName)
	}
	expectedArgs := []string{"-t", "1", "-m", "--", "systemctl", "restart", "k3s"}
	if len(capturedArgs) != len(expectedArgs) {
		t.Fatalf("expected args %v, got %v", expectedArgs, capturedArgs)
	}
	for i, arg := range expectedArgs {
		if capturedArgs[i] != arg {
			t.Errorf("arg[%d]: expected %q, got %q", i, arg, capturedArgs[i])
		}
	}
}

func TestRestartService_ReturnsError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(name string, args ...string) execCmd {
		return &fakeCmd{output: []byte("failed to restart"), err: fmt.Errorf("exit status 1")}
	}

	err := RestartService("k3s")
	if err == nil {
		t.Fatal("expected error from failed restart")
	}
}

func TestWaitForHealth_BecomesHealthy(t *testing.T) {
	// WaitForHealth should return nil when node becomes Ready.
	clientset := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "plato-k3s"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
		},
	})
	rc := NewRestartCoordinator(clientset, "infrastructure", "plato-k3s", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := rc.WaitForHealth(ctx, "k3s", 5*time.Second)
	if err != nil {
		t.Fatalf("expected nil error when node is Ready, got: %v", err)
	}
}

func TestWaitForHealth_Timeout(t *testing.T) {
	// WaitForHealth should return error when node never becomes Ready (circuit breaker).
	clientset := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "plato-k3s"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			},
		},
	})
	rc := NewRestartCoordinator(clientset, "infrastructure", "plato-k3s", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := rc.WaitForHealth(ctx, "k3s", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error when node is not Ready")
	}
}

func TestConcurrentLock_MaxConcurrent1(t *testing.T) {
	// With maxConcurrent=1, only one node should hold the lock.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	// plato tries to acquire — should fail
	rc1 := newTestCoordinator(t, "plato-k3s", 1, cm)
	acquired, err := rc1.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquired {
		t.Fatal("plato should NOT acquire lock when aristotle is restarting (maxConcurrent=1)")
	}
}

func TestConcurrentLock_MaxConcurrent2(t *testing.T) {
	// With maxConcurrent=2, a second node should be allowed.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 2, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("plato SHOULD acquire lock when maxConcurrent=2 and only 1 node restarting")
	}
}

func TestConcurrentLock_MaxConcurrent2_Full(t *testing.T) {
	// With maxConcurrent=2, a third node should be blocked.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
		"socrates-k3s": {
			NodeName:  "socrates-k3s",
			Status:    "restarting",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 2, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquired {
		t.Fatal("plato should NOT acquire lock when 2 nodes already restarting (maxConcurrent=2)")
	}
}

func TestAcquireLock_HealthyNodesNotCounted(t *testing.T) {
	// Nodes with status "healthy" should not count toward maxConcurrent.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "healthy",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 1, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock to be acquired when only healthy nodes exist")
	}
}

func TestAcquireLock_FailedNodesNotCounted(t *testing.T) {
	// Nodes with status "failed" should not count toward maxConcurrent.
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "failed",
			Timestamp: time.Now(),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 1, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock to be acquired when only failed nodes exist")
	}
}

func TestAcquireLock_OwnNodeCanReacquire(t *testing.T) {
	// If this node already has a "restarting" entry, it should be able to re-acquire
	// (idempotent — same node re-entering).
	states := map[string]RestartState{
		"plato-k3s": {
			NodeName:  "plato-k3s",
			Status:    "restarting",
			Timestamp: time.Now().Add(-1 * time.Minute),
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 1, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected own node to re-acquire its lock")
	}
}

func TestReleaseLock_NoConfigMap(t *testing.T) {
	// ReleaseLock when ConfigMap doesn't exist should return an error.
	rc := newTestCoordinator(t, "plato-k3s", 1)

	err := rc.ReleaseLock(context.Background(), "healthy")
	if err == nil {
		t.Fatal("expected error when releasing lock without configmap")
	}
}

func TestAcquireLock_MultipleStaleCleanup(t *testing.T) {
	// Multiple stale locks should all be cleaned up.
	staleTime := time.Now().Add(-10 * time.Minute)
	states := map[string]RestartState{
		"aristotle-k3s": {
			NodeName:  "aristotle-k3s",
			Status:    "restarting",
			Timestamp: staleTime,
			Service:   "k3s",
		},
		"socrates-k3s": {
			NodeName:  "socrates-k3s",
			Status:    "restarting",
			Timestamp: staleTime,
			Service:   "k3s",
		},
	}
	cm := makeRestartStateCM(states)

	rc := newTestCoordinator(t, "plato-k3s", 1, cm)
	acquired, err := rc.AcquireLock(context.Background(), "k3s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock after cleaning up multiple stale entries")
	}
}

func TestWaitForHealth_NoNodeFound(t *testing.T) {
	// WaitForHealth should return error if node doesn't exist.
	clientset := fake.NewSimpleClientset() // no nodes
	rc := NewRestartCoordinator(clientset, "infrastructure", "plato-k3s", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := rc.WaitForHealth(ctx, "k3s", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when node doesn't exist")
	}
}

// fakeCmd implements the execCmd interface for testing.
type fakeCmd struct {
	output []byte
	err    error
}

func (f *fakeCmd) CombinedOutput() ([]byte, error) {
	return f.output, f.err
}

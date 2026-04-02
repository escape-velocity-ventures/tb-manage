package reconciler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// helperWriteFile creates a file with content for testing.
func helperWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create dir %s: %v", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

// helperReadFile reads a file and returns its content.
func helperReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(data)
}

// helperConfigMap creates a ConfigMap with reconciler annotations for testing.
func helperConfigMap(name, namespace, targetPath, mergeStrategy, nodeSelector, restartService, configData string) *corev1.ConfigMap {
	annotations := map[string]string{
		AnnotationTargetPath:    targetPath,
		AnnotationMergeStrategy: mergeStrategy,
	}
	if nodeSelector != "" {
		annotations[AnnotationNodeSelector] = nodeSelector
	}
	if restartService != "" {
		annotations[AnnotationRestartService] = restartService
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				LabelConfigReconciler: "true",
			},
			Annotations: annotations,
		},
		Data: map[string]string{
			"config.yaml": configData,
		},
	}
}

func TestRunOnce_NoTargets(t *testing.T) {
	client := fake.NewSimpleClientset()
	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, "/tmp/test-host-root")

	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestRunOnce_OneTarget_NoChange(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	// Existing file matches what ConfigMap will produce after merge
	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	// The ConfigMap data
	configData := "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n"

	// Write existing file with content that matches what merge would produce
	// (for "replace" strategy, the file content == configMap data after re-marshal)
	// Use replace strategy to simplify: desired content == configData re-marshaled
	merged, err := Merge(nil, []byte(configData), "replace")
	if err != nil {
		t.Fatalf("pre-merge failed: %v", err)
	}
	helperWriteFile(t, fullPath, string(merged))

	client := fake.NewSimpleClientset(
		helperConfigMap("k3s-server-config", "infrastructure", targetPath, "replace", "", "", configData),
	)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Changed {
		t.Error("expected no change, but Changed=true")
	}
	if results[0].Error != nil {
		t.Errorf("expected no error, got: %v", results[0].Error)
	}
	if results[0].ConfigMapName != "k3s-server-config" {
		t.Errorf("expected ConfigMapName='k3s-server-config', got %q", results[0].ConfigMapName)
	}
}

func TestRunOnce_OneTarget_ChangeDetected_WriteAndRestart(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	// Write existing file with different content
	helperWriteFile(t, fullPath, "data-dir: /var/lib/rancher/k3s\n")

	configData := "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n"

	client := fake.NewSimpleClientset(
		helperConfigMap("k3s-server-config", "infrastructure", targetPath, "merge", "", "k3s", configData),
	)

	// Mock execCommand so RestartService doesn't actually call nsenter
	origExecCommand := execCommand
	var restartCalled bool
	execCommand = func(name string, args ...string) execCmd {
		restartCalled = true
		return &mockCmd{output: []byte(""), err: nil}
	}
	defer func() { execCommand = origExecCommand }()

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)

	// Mock WaitForHealth by using a short timeout and pre-creating a ready node
	_, err := client.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create fake node: %v", err)
	}

	results, runErr := r.RunOnce(context.Background())
	if runErr != nil {
		t.Fatalf("expected no error, got: %v", runErr)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Changed {
		t.Error("expected Changed=true")
	}
	if !results[0].Restarted {
		t.Error("expected Restarted=true")
	}
	if !restartCalled {
		t.Error("expected RestartService to be called")
	}

	// Verify file was updated (should contain merged content)
	content := helperReadFile(t, fullPath)
	if content == "data-dir: /var/lib/rancher/k3s\n" {
		t.Error("file was not updated")
	}
}

func TestRunOnce_DryRun_NoWritesNoRestarts(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	// Write existing file with different content so there would be a change
	helperWriteFile(t, fullPath, "data-dir: /var/lib/rancher/k3s\n")

	configData := "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n"

	client := fake.NewSimpleClientset(
		helperConfigMap("k3s-server-config", "infrastructure", targetPath, "merge", "", "k3s", configData),
	)

	// Mock execCommand
	origExecCommand := execCommand
	var restartCalled bool
	execCommand = func(name string, args ...string) execCmd {
		restartCalled = true
		return &mockCmd{output: []byte(""), err: nil}
	}
	defer func() { execCommand = origExecCommand }()

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, true, hostRoot) // dryRun=true

	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// In dry-run, Changed reflects what WOULD happen
	if !results[0].Changed {
		t.Error("expected Changed=true (would change)")
	}
	if results[0].Restarted {
		t.Error("expected Restarted=false in dry-run mode")
	}
	if restartCalled {
		t.Error("restart should NOT be called in dry-run mode")
	}

	// Verify file was NOT modified
	content := helperReadFile(t, fullPath)
	if content != "data-dir: /var/lib/rancher/k3s\n" {
		t.Error("file should not be modified in dry-run mode")
	}
}

func TestRunOnce_RestartLockUnavailable(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	helperWriteFile(t, fullPath, "data-dir: /var/lib/rancher/k3s\n")

	configData := "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n"

	// Pre-create restart-state ConfigMap with another node restarting
	restartStateCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tb-manage-restart-state",
			Namespace: "infrastructure",
		},
		Data: map[string]string{
			"node-2": fmt.Sprintf(`{"nodeName":"node-2","status":"restarting","timestamp":"%s","service":"k3s"}`,
				time.Now().Format(time.RFC3339)),
		},
	}

	client := fake.NewSimpleClientset(
		helperConfigMap("k3s-server-config", "infrastructure", targetPath, "merge", "", "k3s", configData),
		restartStateCM,
	)

	// Mock execCommand
	origExecCommand := execCommand
	var restartCalled bool
	execCommand = func(name string, args ...string) execCmd {
		restartCalled = true
		return &mockCmd{output: []byte(""), err: nil}
	}
	defer func() { execCommand = origExecCommand }()

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)

	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// File should still be written even if restart is deferred
	if !results[0].Changed {
		t.Error("expected Changed=true (file was written)")
	}
	if results[0].Restarted {
		t.Error("expected Restarted=false (lock unavailable)")
	}
	if restartCalled {
		t.Error("restart should NOT be called when lock is unavailable")
	}
}

func TestRunOnce_MultipleTargets(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	// Target 1: config that will change
	path1 := "/etc/rancher/k3s/config.yaml"
	fullPath1 := filepath.Join(hostRoot, path1)
	helperWriteFile(t, fullPath1, "data-dir: /var/lib/rancher/k3s\n")

	// Target 2: sysctl config (replace strategy, no restart)
	path2 := "/etc/sysctl.d/99-k8s.conf"
	fullPath2 := filepath.Join(hostRoot, path2)
	helperWriteFile(t, fullPath2, "net.ipv4.ip_forward: \"1\"\n")

	cm1 := helperConfigMap("k3s-server-config", "infrastructure", path1, "merge", "", "", "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n")
	cm2 := helperConfigMap("sysctl-config", "infrastructure", path2, "replace", "", "", "net.ipv4.ip_forward: \"1\"\nnet.bridge.bridge-nf-call-iptables: \"1\"\n")

	client := fake.NewSimpleClientset(cm1, cm2)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// At least one should be changed
	anyChanged := false
	for _, r := range results {
		if r.Changed {
			anyChanged = true
		}
	}
	if !anyChanged {
		t.Error("expected at least one target to have changes")
	}
}

func TestRunOnce_ListTargetsError(t *testing.T) {
	// Use a client with a reactor that always fails
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("simulated API error")
	})
	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, "/tmp/host")

	_, err := r.RunOnce(context.Background())
	if err == nil {
		t.Error("expected error from ListTargets failure, got nil")
	}
}

func TestRunOnce_MergeError_SkipsTarget(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	// Write valid existing file
	helperWriteFile(t, fullPath, "data-dir: /var/lib/rancher/k3s\n")

	// ConfigMap with invalid YAML data — this will cause Merge to fail
	cm := helperConfigMap("bad-config", "infrastructure", targetPath, "merge", "", "", "{{invalid yaml")

	client := fake.NewSimpleClientset(cm)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce should not return error for merge failure, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected error in result for bad YAML")
	}
	if results[0].Changed {
		t.Error("should not report Changed for failed merge")
	}
}

func TestRunOnce_WriteError_SkipsRestart(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	// Target path in a directory that doesn't exist and can't be created
	// (we don't pre-create it, and the dir won't exist under hostRoot)
	targetPath := "/nonexistent/deep/path/config.yaml"
	// Don't create the directory — WriteFile will fail

	configData := "key: value\n"

	client := fake.NewSimpleClientset(
		helperConfigMap("fail-write", "infrastructure", targetPath, "replace", "", "k3s", configData),
	)

	// Mock execCommand
	origExecCommand := execCommand
	var restartCalled bool
	execCommand = func(name string, args ...string) execCmd {
		restartCalled = true
		return &mockCmd{output: []byte(""), err: nil}
	}
	defer func() { execCommand = origExecCommand }()

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce should not return error for write failure, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected error in result for write failure")
	}
	if restartCalled {
		t.Error("restart should NOT be called after write failure")
	}
}

func TestRunOnce_NodeSelectorFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"

	configData := "key: value\n"

	// ConfigMap requires control-plane label
	cm := helperConfigMap("k3s-server-config", "infrastructure", targetPath, "replace",
		"node-role.kubernetes.io/control-plane=true", "", configData)

	client := fake.NewSimpleClientset(cm)

	// Node WITHOUT the required label
	r := New(client, "infrastructure", "node-1", map[string]string{"other-label": "true"}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results (node doesn't match selector), got %d", len(results))
	}

	// Now with matching label
	r2 := New(client, "infrastructure", "node-1",
		map[string]string{"node-role.kubernetes.io/control-plane": "true"},
		60*time.Second, false, hostRoot)

	fullPath := filepath.Join(hostRoot, targetPath)
	helperWriteFile(t, fullPath, "old: content\n")

	results2, err2 := r2.RunOnce(context.Background())
	if err2 != nil {
		t.Fatalf("expected no error, got: %v", err2)
	}
	if len(results2) != 1 {
		t.Fatalf("expected 1 result (node matches selector), got %d", len(results2))
	}
}

func TestRunOnce_HostRootPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	configData := "key: value\n"

	// Write file at the host-root-prefixed path
	helperWriteFile(t, fullPath, "old: content\n")

	client := fake.NewSimpleClientset(
		helperConfigMap("test-cm", "infrastructure", targetPath, "replace", "", "", configData),
	)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Changed {
		t.Error("expected Changed=true")
	}

	// Verify the file at the prefixed path was updated
	content := helperReadFile(t, fullPath)
	if content == "old: content\n" {
		t.Error("file at host-root-prefixed path was not updated")
	}
}

func TestRunOnce_MergeStrategy_ExistingFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)

	// Ensure directory exists but file doesn't
	os.MkdirAll(filepath.Dir(fullPath), 0755)

	configData := "kube-apiserver-arg:\n    - oidc-issuer-url=https://example.com\n"

	client := fake.NewSimpleClientset(
		helperConfigMap("k3s-server-config", "infrastructure", targetPath, "merge", "", "", configData),
	)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Changed {
		t.Error("expected Changed=true for new file")
	}
	if results[0].Error != nil {
		t.Errorf("expected no error, got: %v", results[0].Error)
	}

	// File should now exist
	content := helperReadFile(t, fullPath)
	if content == "" {
		t.Error("file should have been created")
	}
}

func TestRunOnce_ConfigMapDataKey(t *testing.T) {
	tmpDir := t.TempDir()
	hostRoot := tmpDir

	targetPath := "/etc/rancher/k3s/config.yaml"
	fullPath := filepath.Join(hostRoot, targetPath)
	helperWriteFile(t, fullPath, "old: content\n")

	// ConfigMap with config.yaml key
	configData := "new: content\n"
	client := fake.NewSimpleClientset(
		helperConfigMap("test-cm", "infrastructure", targetPath, "replace", "", "", configData),
	)

	r := New(client, "infrastructure", "node-1", map[string]string{}, 60*time.Second, false, hostRoot)
	results, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Changed {
		t.Error("expected Changed=true")
	}
}

func TestReconcileResult_Fields(t *testing.T) {
	r := ReconcileResult{
		ConfigMapName: "test-cm",
		TargetPath:    "/etc/config.yaml",
		Changed:       true,
		Restarted:     false,
		Error:         fmt.Errorf("test error"),
	}
	if r.ConfigMapName != "test-cm" {
		t.Error("ConfigMapName mismatch")
	}
	if r.TargetPath != "/etc/config.yaml" {
		t.Error("TargetPath mismatch")
	}
	if !r.Changed {
		t.Error("Changed should be true")
	}
	if r.Restarted {
		t.Error("Restarted should be false")
	}
	if r.Error == nil {
		t.Error("Error should not be nil")
	}
}

func TestNew_CreatesReconciler(t *testing.T) {
	client := fake.NewSimpleClientset()
	r := New(client, "infrastructure", "node-1", map[string]string{"a": "b"}, 30*time.Second, true, "/host")

	if r == nil {
		t.Fatal("expected non-nil Reconciler")
	}
	if r.namespace != "infrastructure" {
		t.Errorf("expected namespace='infrastructure', got %q", r.namespace)
	}
	if r.nodeName != "node-1" {
		t.Errorf("expected nodeName='node-1', got %q", r.nodeName)
	}
	if r.interval != 30*time.Second {
		t.Errorf("expected interval=30s, got %s", r.interval)
	}
	if !r.dryRun {
		t.Error("expected dryRun=true")
	}
	if r.hostRoot != "/host" {
		t.Errorf("expected hostRoot='/host', got %q", r.hostRoot)
	}
}

func TestRun_CancelledContext(t *testing.T) {
	client := fake.NewSimpleClientset()
	r := New(client, "infrastructure", "node-1", map[string]string{}, 1*time.Second, false, "/tmp/test")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := r.Run(ctx)
	if err != nil {
		t.Fatalf("expected nil error from cancelled Run, got: %v", err)
	}
}

// mockCmd implements execCmd for testing.
type mockCmd struct {
	output []byte
	err    error
}

func (m *mockCmd) CombinedOutput() ([]byte, error) {
	return m.output, m.err
}

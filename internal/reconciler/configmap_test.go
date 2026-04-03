package reconciler

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- ParseNodeSelector tests ---

func TestParseNodeSelector_Single(t *testing.T) {
	got := ParseNodeSelector("role=control-plane")
	if len(got) != 1 || got["role"] != "control-plane" {
		t.Errorf("ParseNodeSelector single: got %v", got)
	}
}

func TestParseNodeSelector_Multiple(t *testing.T) {
	got := ParseNodeSelector("role=control-plane,zone=us-west-1")
	if len(got) != 2 || got["role"] != "control-plane" || got["zone"] != "us-west-1" {
		t.Errorf("ParseNodeSelector multiple: got %v", got)
	}
}

func TestParseNodeSelector_Empty(t *testing.T) {
	got := ParseNodeSelector("")
	if got == nil || len(got) != 0 {
		t.Errorf("ParseNodeSelector empty: expected empty map, got %v", got)
	}
}

func TestParseNodeSelector_WhitespaceHandling(t *testing.T) {
	got := ParseNodeSelector(" role = control-plane , zone = rack1 ")
	if len(got) != 2 || got["role"] != "control-plane" || got["zone"] != "rack1" {
		t.Errorf("ParseNodeSelector whitespace: got %v", got)
	}
}

func TestParseNodeSelector_MalformedEntrySkipped(t *testing.T) {
	got := ParseNodeSelector("role=control-plane,badentry,zone=rack1")
	if len(got) != 2 || got["role"] != "control-plane" || got["zone"] != "rack1" {
		t.Errorf("ParseNodeSelector malformed: got %v", got)
	}
}

// --- MatchesNode tests ---

func TestMatchesNode_EmptySelector(t *testing.T) {
	target := ReconcileTarget{NodeSelector: map[string]string{}}
	if !MatchesNode(target, map[string]string{"role": "worker"}) {
		t.Error("empty selector should match all nodes")
	}
}

func TestMatchesNode_NilSelector(t *testing.T) {
	target := ReconcileTarget{NodeSelector: nil}
	if !MatchesNode(target, map[string]string{"role": "worker"}) {
		t.Error("nil selector should match all nodes")
	}
}

func TestMatchesNode_Match(t *testing.T) {
	target := ReconcileTarget{
		NodeSelector: map[string]string{"node-role.kubernetes.io/control-plane": "true"},
	}
	nodeLabels := map[string]string{
		"node-role.kubernetes.io/control-plane": "true",
		"kubernetes.io/hostname":                "plato",
	}
	if !MatchesNode(target, nodeLabels) {
		t.Error("expected match for control-plane node")
	}
}

func TestMatchesNode_NoMatch(t *testing.T) {
	target := ReconcileTarget{
		NodeSelector: map[string]string{"node-role.kubernetes.io/control-plane": "true"},
	}
	nodeLabels := map[string]string{
		"kubernetes.io/hostname": "worker-1",
	}
	if MatchesNode(target, nodeLabels) {
		t.Error("expected no match for worker node without control-plane label")
	}
}

func TestMatchesNode_PartialMatch(t *testing.T) {
	target := ReconcileTarget{
		NodeSelector: map[string]string{
			"role": "control-plane",
			"zone": "rack1",
		},
	}
	nodeLabels := map[string]string{
		"role": "control-plane",
		// missing "zone"
	}
	if MatchesNode(target, nodeLabels) {
		t.Error("partial match (missing label) should not match")
	}
}

func TestMatchesNode_ValueMismatch(t *testing.T) {
	target := ReconcileTarget{
		NodeSelector: map[string]string{"zone": "rack1"},
	}
	nodeLabels := map[string]string{"zone": "rack2"}
	if MatchesNode(target, nodeLabels) {
		t.Error("value mismatch should not match")
	}
}

// --- ListTargets tests ---

func makeConfigMap(name, namespace string, labels, annotations map[string]string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          labels,
			Annotations:     annotations,
			ResourceVersion: "12345",
		},
		Data: data,
	}
}

func TestListTargets_BasicTarget(t *testing.T) {
	cm := makeConfigMap("k3s-server-config", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path":     "/etc/rancher/k3s/config.yaml",
			"tb.io/merge-strategy":  "merge",
			"tb.io/node-selector":   "node-role.kubernetes.io/control-plane=true",
			"tb.io/restart-service": "k3s",
			"tb.io/max-concurrent":  "2",
		},
		map[string]string{"config.yaml": "kube-apiserver-arg:\n  - oidc-issuer-url=test\n"},
	)

	client := fake.NewSimpleClientset(cm)
	nodeLabels := map[string]string{"node-role.kubernetes.io/control-plane": "true"}

	targets, err := ListTargets(context.Background(), client, "infrastructure", nodeLabels)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	tgt := targets[0]
	if tgt.ConfigMapName != "k3s-server-config" {
		t.Errorf("ConfigMapName: got %q", tgt.ConfigMapName)
	}
	if tgt.Namespace != "infrastructure" {
		t.Errorf("Namespace: got %q", tgt.Namespace)
	}
	if tgt.TargetPath != "/etc/rancher/k3s/config.yaml" {
		t.Errorf("TargetPath: got %q", tgt.TargetPath)
	}
	if tgt.MergeStrategy != "merge" {
		t.Errorf("MergeStrategy: got %q", tgt.MergeStrategy)
	}
	if tgt.RestartService != "k3s" {
		t.Errorf("RestartService: got %q", tgt.RestartService)
	}
	if tgt.MaxConcurrent != 2 {
		t.Errorf("MaxConcurrent: got %d", tgt.MaxConcurrent)
	}
	if tgt.ResourceVersion != "12345" {
		t.Errorf("ResourceVersion: got %q", tgt.ResourceVersion)
	}
	if len(tgt.Data) != 1 {
		t.Errorf("Data length: got %d", len(tgt.Data))
	}
	if tgt.NodeSelector["node-role.kubernetes.io/control-plane"] != "true" {
		t.Errorf("NodeSelector: got %v", tgt.NodeSelector)
	}
}

func TestListTargets_FiltersByLabel(t *testing.T) {
	labeled := makeConfigMap("labeled", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/test.yaml"},
		map[string]string{"test": "data"},
	)
	unlabeled := makeConfigMap("unlabeled", "infrastructure",
		map[string]string{"app": "something-else"},
		map[string]string{"tb.io/target-path": "/etc/other.yaml"},
		map[string]string{"other": "data"},
	)

	client := fake.NewSimpleClientset(labeled, unlabeled)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target (only labeled), got %d", len(targets))
	}
	if targets[0].ConfigMapName != "labeled" {
		t.Errorf("expected 'labeled', got %q", targets[0].ConfigMapName)
	}
}

func TestListTargets_FiltersByNodeSelector(t *testing.T) {
	cm := makeConfigMap("server-only", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path":   "/etc/test.yaml",
			"tb.io/node-selector": "node-role.kubernetes.io/control-plane=true",
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	// Worker node without control-plane label
	workerLabels := map[string]string{"kubernetes.io/hostname": "worker-1"}

	targets, err := ListTargets(context.Background(), client, "infrastructure", workerLabels)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets for worker node, got %d", len(targets))
	}
}

func TestListTargets_DefaultValues(t *testing.T) {
	cm := makeConfigMap("minimal", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path": "/etc/test.yaml",
			// no merge-strategy, no max-concurrent
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	tgt := targets[0]
	if tgt.MergeStrategy != "merge" {
		t.Errorf("default MergeStrategy: got %q, want %q", tgt.MergeStrategy, "merge")
	}
	if tgt.MaxConcurrent != 1 {
		t.Errorf("default MaxConcurrent: got %d, want %d", tgt.MaxConcurrent, 1)
	}
}

func TestListTargets_MissingTargetPathSkipped(t *testing.T) {
	noPath := makeConfigMap("no-path", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/merge-strategy": "replace",
			// missing tb.io/target-path
		},
		map[string]string{"test": "data"},
	)
	withPath := makeConfigMap("with-path", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/valid.yaml"},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(noPath, withPath)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target (missing path skipped), got %d", len(targets))
	}
	if targets[0].ConfigMapName != "with-path" {
		t.Errorf("expected 'with-path', got %q", targets[0].ConfigMapName)
	}
}

func TestListTargets_InvalidMaxConcurrentDefaultsToOne(t *testing.T) {
	cm := makeConfigMap("bad-concurrent", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path":    "/etc/test.yaml",
			"tb.io/max-concurrent": "not-a-number",
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].MaxConcurrent != 1 {
		t.Errorf("invalid max-concurrent should default to 1, got %d", targets[0].MaxConcurrent)
	}
}

func TestListTargets_MultipleConfigMaps(t *testing.T) {
	cm1 := makeConfigMap("k3s-config", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/rancher/k3s/config.yaml"},
		map[string]string{"config.yaml": "data1"},
	)
	cm2 := makeConfigMap("sysctl-config", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/sysctl.d/99-custom.conf"},
		map[string]string{"99-custom.conf": "data2"},
	)

	client := fake.NewSimpleClientset(cm1, cm2)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestListTargets_EmptyNamespace(t *testing.T) {
	cm := makeConfigMap("config", "other-ns",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/test.yaml"},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	// Querying "infrastructure" should not find ConfigMap in "other-ns"
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets in wrong namespace, got %d", len(targets))
	}
}

func TestListTargets_ReplaceStrategy(t *testing.T) {
	cm := makeConfigMap("replace-config", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path":    "/etc/test.yaml",
			"tb.io/merge-strategy": "replace",
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].MergeStrategy != "replace" {
		t.Errorf("MergeStrategy: got %q, want %q", targets[0].MergeStrategy, "replace")
	}
}

func TestListTargets_EmptyNodeSelectorMatchesAll(t *testing.T) {
	cm := makeConfigMap("all-nodes", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path": "/etc/test.yaml",
			// no node-selector annotation
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{"anything": "here"})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target (empty selector matches all), got %d", len(targets))
	}
}

func TestListTargets_PreservesConfigMapData(t *testing.T) {
	data := map[string]string{
		"config.yaml": "key1: value1\nkey2: value2\n",
		"extra.yaml":  "extra: true\n",
	}
	cm := makeConfigMap("multi-key", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{"tb.io/target-path": "/etc/test.yaml"},
		data,
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if len(targets[0].Data) != 2 {
		t.Errorf("expected 2 data keys, got %d", len(targets[0].Data))
	}
	if targets[0].Data["config.yaml"] != data["config.yaml"] {
		t.Errorf("data mismatch for config.yaml")
	}
	if targets[0].Data["extra.yaml"] != data["extra.yaml"] {
		t.Errorf("data mismatch for extra.yaml")
	}
}

func TestListTargets_ZeroMaxConcurrentDefaultsToOne(t *testing.T) {
	cm := makeConfigMap("zero-concurrent", "infrastructure",
		map[string]string{"tb.io/config-reconciler": "true"},
		map[string]string{
			"tb.io/target-path":    "/etc/test.yaml",
			"tb.io/max-concurrent": "0",
		},
		map[string]string{"test": "data"},
	)

	client := fake.NewSimpleClientset(cm)
	targets, err := ListTargets(context.Background(), client, "infrastructure", map[string]string{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].MaxConcurrent != 1 {
		t.Errorf("zero max-concurrent should default to 1, got %d", targets[0].MaxConcurrent)
	}
}

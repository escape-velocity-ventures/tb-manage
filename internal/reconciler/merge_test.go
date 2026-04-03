package reconciler

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// helper: parse YAML string to map
func mustParse(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("mustParse: %v", err)
	}
	return m
}

// helper: convert result bytes to map for assertions
func mustParseBytes(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("mustParseBytes: %v", err)
	}
	return m
}

// helper: extract string slice from interface{}
func toStringSlice(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", v)
	}
	out := make([]string, len(raw))
	for i, item := range raw {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("expected string at index %d, got %T", i, item)
		}
		out[i] = s
	}
	return out
}

// --- Merge() function tests ---

func TestMerge_ReplaceStrategy_ReturnsDesiredUnchanged(t *testing.T) {
	existing := []byte("foo: bar\nbaz: qux\n")
	desired := []byte("completely: different\n")

	result, err := Merge(existing, desired, "replace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["completely"] != "different" {
		t.Errorf("expected 'different', got %v", m["completely"])
	}
	if _, exists := m["foo"]; exists {
		t.Error("replace strategy should not preserve base keys")
	}
}

func TestMerge_MergeStrategy_DisjointKeys(t *testing.T) {
	existing := []byte("alpha: 1\n")
	desired := []byte("beta: 2\n")

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["alpha"] != 1 {
		t.Errorf("expected alpha=1, got %v", m["alpha"])
	}
	if m["beta"] != 2 {
		t.Errorf("expected beta=2, got %v", m["beta"])
	}
}

func TestMerge_MergeStrategy_OverlappingScalar_OverlayWins(t *testing.T) {
	existing := []byte("name: old\nversion: 1\n")
	desired := []byte("name: new\n")

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["name"] != "new" {
		t.Errorf("expected name=new, got %v", m["name"])
	}
	if m["version"] != 1 {
		t.Errorf("expected version=1 preserved, got %v", m["version"])
	}
}

func TestMerge_MergeStrategy_NestedMaps(t *testing.T) {
	existing := []byte(`
server:
  host: localhost
  port: 8080
  tls: false
`)
	desired := []byte(`
server:
  port: 9090
  tls: true
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	server, ok := m["server"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected server to be a map, got %T", m["server"])
	}
	if server["host"] != "localhost" {
		t.Errorf("expected host=localhost preserved, got %v", server["host"])
	}
	if server["port"] != 9090 {
		t.Errorf("expected port=9090, got %v", server["port"])
	}
	if server["tls"] != true {
		t.Errorf("expected tls=true, got %v", server["tls"])
	}
}

func TestMerge_MergeStrategy_SliceAppend(t *testing.T) {
	existing := []byte(`
args:
  - "--flag-a"
  - "--flag-b"
`)
	desired := []byte(`
args:
  - "--flag-c"
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	items := toStringSlice(t, m["args"])
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(items), items)
	}
	expected := []string{"--flag-a", "--flag-b", "--flag-c"}
	for i, e := range expected {
		if items[i] != e {
			t.Errorf("index %d: expected %q, got %q", i, e, items[i])
		}
	}
}

func TestMerge_MergeStrategy_SliceDedup(t *testing.T) {
	existing := []byte(`
args:
  - "--flag-a"
  - "--flag-b"
`)
	desired := []byte(`
args:
  - "--flag-b"
  - "--flag-c"
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	items := toStringSlice(t, m["args"])
	if len(items) != 3 {
		t.Fatalf("expected 3 items (deduped), got %d: %v", len(items), items)
	}
	// flag-b should appear exactly once
	count := 0
	for _, item := range items {
		if item == "--flag-b" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected --flag-b once, found %d times", count)
	}
}

func TestMerge_MergeStrategy_EmptyBase(t *testing.T) {
	existing := []byte("")
	desired := []byte("key: value\n")

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["key"] != "value" {
		t.Errorf("expected key=value, got %v", m["key"])
	}
}

func TestMerge_MergeStrategy_EmptyOverlay(t *testing.T) {
	existing := []byte("key: value\n")
	desired := []byte("")

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["key"] != "value" {
		t.Errorf("expected key=value preserved, got %v", m["key"])
	}
}

func TestMerge_MalformedExistingYAML_ReturnsError(t *testing.T) {
	existing := []byte(":\n  bad: [yaml\n  missing: bracket")
	desired := []byte("key: value\n")

	_, err := Merge(existing, desired, "merge")
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestMerge_MalformedDesiredYAML_ReturnsError(t *testing.T) {
	existing := []byte("key: value\n")
	desired := []byte(":\n  bad: [yaml\n  missing: bracket")

	_, err := Merge(existing, desired, "merge")
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestMerge_PreservesBaseKeysNotInOverlay(t *testing.T) {
	existing := []byte(`
alpha: 1
beta: 2
gamma: 3
`)
	desired := []byte(`
beta: 22
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["alpha"] != 1 {
		t.Errorf("expected alpha=1 preserved, got %v", m["alpha"])
	}
	if m["beta"] != 22 {
		t.Errorf("expected beta=22, got %v", m["beta"])
	}
	if m["gamma"] != 3 {
		t.Errorf("expected gamma=3 preserved, got %v", m["gamma"])
	}
}

func TestMerge_UnknownStrategy_ReturnsError(t *testing.T) {
	_, err := Merge([]byte("a: 1"), []byte("b: 2"), "unknown")
	if err == nil {
		t.Error("expected error for unknown strategy")
	}
}

// --- DeepMergeYAML direct tests ---

func TestDeepMergeYAML_NilBase(t *testing.T) {
	overlay := map[string]interface{}{"key": "value"}
	result := DeepMergeYAML(nil, overlay)
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}
}

func TestDeepMergeYAML_NilOverlay(t *testing.T) {
	base := map[string]interface{}{"key": "value"}
	result := DeepMergeYAML(base, nil)
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}
}

func TestDeepMergeYAML_BothNil(t *testing.T) {
	result := DeepMergeYAML(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestDeepMergeYAML_DeeplyNestedMaps(t *testing.T) {
	base := mustParse(t, `
level1:
  level2:
    level3:
      base-key: base-value
`)
	overlay := mustParse(t, `
level1:
  level2:
    level3:
      overlay-key: overlay-value
`)
	result := DeepMergeYAML(base, overlay)

	l1, _ := result["level1"].(map[string]interface{})
	l2, _ := l1["level2"].(map[string]interface{})
	l3, _ := l2["level3"].(map[string]interface{})

	if l3["base-key"] != "base-value" {
		t.Errorf("expected base-key preserved, got %v", l3["base-key"])
	}
	if l3["overlay-key"] != "overlay-value" {
		t.Errorf("expected overlay-key added, got %v", l3["overlay-key"])
	}
}

func TestDeepMergeYAML_MapOverridesScalar(t *testing.T) {
	// If overlay has a map where base has a scalar, overlay wins
	base := map[string]interface{}{"key": "scalar"}
	overlay := map[string]interface{}{
		"key": map[string]interface{}{"nested": "value"},
	}
	result := DeepMergeYAML(base, overlay)
	m, ok := result["key"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result["key"])
	}
	if m["nested"] != "value" {
		t.Errorf("expected nested=value, got %v", m["nested"])
	}
}

func TestDeepMergeYAML_ScalarOverridesMap(t *testing.T) {
	// If overlay has a scalar where base has a map, overlay wins
	base := map[string]interface{}{
		"key": map[string]interface{}{"nested": "value"},
	}
	overlay := map[string]interface{}{"key": "scalar"}
	result := DeepMergeYAML(base, overlay)
	if result["key"] != "scalar" {
		t.Errorf("expected scalar, got %v", result["key"])
	}
}

func TestDeepMergeYAML_SliceWithNonStringItems(t *testing.T) {
	// Mixed-type slices: overlay replaces (can't dedup non-strings meaningfully)
	base := map[string]interface{}{
		"items": []interface{}{1, 2, 3},
	}
	overlay := map[string]interface{}{
		"items": []interface{}{4, 5},
	}
	result := DeepMergeYAML(base, overlay)
	items, ok := result["items"].([]interface{})
	if !ok {
		t.Fatalf("expected slice, got %T", result["items"])
	}
	// Should append unique items
	if len(items) != 5 {
		t.Errorf("expected 5 items, got %d: %v", len(items), items)
	}
}

func TestDeepMergeYAML_SliceWithDuplicateNonStrings(t *testing.T) {
	base := map[string]interface{}{
		"ports": []interface{}{80, 443},
	}
	overlay := map[string]interface{}{
		"ports": []interface{}{443, 8080},
	}
	result := DeepMergeYAML(base, overlay)
	items, ok := result["ports"].([]interface{})
	if !ok {
		t.Fatalf("expected slice, got %T", result["ports"])
	}
	// 80, 443, 8080 (443 deduped)
	if len(items) != 3 {
		t.Errorf("expected 3 items (deduped), got %d: %v", len(items), items)
	}
}

// --- Real-world k3s scenario tests ---

func TestMerge_RealK3sConfig_NodeLabelPlusOIDC(t *testing.T) {
	existing := []byte(`node-label:
  - "topology.kubernetes.io/zone=rack1"
data-dir: /var/lib/rancher/k3s
`)
	desired := []byte(`kube-apiserver-arg:
  - "oidc-issuer-url=https://example.com"
  - "oidc-client-id=abc123"
  - "oidc-username-claim=email"
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)

	// Base keys preserved
	labels := toStringSlice(t, m["node-label"])
	if len(labels) != 1 || labels[0] != "topology.kubernetes.io/zone=rack1" {
		t.Errorf("node-label not preserved: %v", labels)
	}
	if m["data-dir"] != "/var/lib/rancher/k3s" {
		t.Errorf("data-dir not preserved: %v", m["data-dir"])
	}

	// Overlay keys added
	oidcArgs := toStringSlice(t, m["kube-apiserver-arg"])
	if len(oidcArgs) != 3 {
		t.Fatalf("expected 3 oidc args, got %d: %v", len(oidcArgs), oidcArgs)
	}
}

func TestMerge_RealK3sConfig_AddNewOIDCArgToExisting(t *testing.T) {
	existing := []byte(`kube-apiserver-arg:
  - "oidc-issuer-url=https://example.com"
  - "oidc-client-id=abc123"
node-label:
  - "topology.kubernetes.io/zone=rack1"
`)
	desired := []byte(`kube-apiserver-arg:
  - "oidc-issuer-url=https://example.com"
  - "oidc-client-id=abc123"
  - "oidc-username-claim=email"
  - "oidc-username-prefix=cf:"
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)

	oidcArgs := toStringSlice(t, m["kube-apiserver-arg"])
	if len(oidcArgs) != 4 {
		t.Fatalf("expected 4 oidc args (2 existing + 2 new), got %d: %v", len(oidcArgs), oidcArgs)
	}

	// Verify no duplicates
	seen := map[string]int{}
	for _, arg := range oidcArgs {
		seen[arg]++
	}
	for arg, count := range seen {
		if count > 1 {
			t.Errorf("duplicate arg: %q appeared %d times", arg, count)
		}
	}

	// node-label preserved
	labels := toStringSlice(t, m["node-label"])
	if len(labels) != 1 {
		t.Errorf("node-label not preserved: %v", labels)
	}
}

func TestMerge_RealK3sConfig_IdempotentReapply(t *testing.T) {
	// Applying the same overlay twice should produce identical results
	existing := []byte(`node-label:
  - "topology.kubernetes.io/zone=rack1"
data-dir: /var/lib/rancher/k3s
`)
	desired := []byte(`kube-apiserver-arg:
  - "oidc-issuer-url=https://example.com"
`)

	first, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("first merge error: %v", err)
	}

	second, err := Merge(first, desired, "merge")
	if err != nil {
		t.Fatalf("second merge error: %v", err)
	}

	// Parse both and compare
	m1 := mustParseBytes(t, first)
	m2 := mustParseBytes(t, second)

	// kube-apiserver-arg should still have exactly 1 entry
	args1 := toStringSlice(t, m1["kube-apiserver-arg"])
	args2 := toStringSlice(t, m2["kube-apiserver-arg"])
	if len(args1) != len(args2) {
		t.Errorf("idempotency broken: first=%v, second=%v", args1, args2)
	}
}

func TestMerge_OutputIs2SpaceIndent(t *testing.T) {
	existing := []byte(`server:
  host: localhost
`)
	desired := []byte(`server:
  port: 9090
`)

	result, err := Merge(existing, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that output uses 2-space indent (not 4-space which is yaml.v3 default)
	s := string(result)
	if strings.Contains(s, "    ") {
		t.Errorf("expected 2-space indent, found 4-space in:\n%s", s)
	}
	if !strings.Contains(s, "  host:") || !strings.Contains(s, "  port:") {
		t.Errorf("expected 2-space indented keys in:\n%s", s)
	}
}

func TestMerge_NilExistingBytes(t *testing.T) {
	desired := []byte("key: value\n")

	result, err := Merge(nil, desired, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["key"] != "value" {
		t.Errorf("expected key=value, got %v", m["key"])
	}
}

func TestMerge_NilDesiredBytes(t *testing.T) {
	existing := []byte("key: value\n")

	result, err := Merge(existing, nil, "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["key"] != "value" {
		t.Errorf("expected key=value preserved, got %v", m["key"])
	}
}

func TestMerge_BothEmpty(t *testing.T) {
	result, err := Merge([]byte(""), []byte(""), "merge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should produce valid empty YAML (either empty or {}\n)
	s := strings.TrimSpace(string(result))
	if s != "{}" && s != "" {
		t.Errorf("expected empty output, got %q", s)
	}
}

func TestMerge_ReplaceStrategyWithNilExisting(t *testing.T) {
	desired := []byte("key: value\n")

	result, err := Merge(nil, desired, "replace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := mustParseBytes(t, result)
	if m["key"] != "value" {
		t.Errorf("expected key=value, got %v", m["key"])
	}
}

func TestDeepMergeYAML_EmptySliceBase(t *testing.T) {
	base := map[string]interface{}{
		"items": []interface{}{},
	}
	overlay := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	result := DeepMergeYAML(base, overlay)
	items := result["items"].([]interface{})
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
}

func TestDeepMergeYAML_EmptySliceOverlay(t *testing.T) {
	base := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	overlay := map[string]interface{}{
		"items": []interface{}{},
	}
	result := DeepMergeYAML(base, overlay)
	items := result["items"].([]interface{})
	if len(items) != 2 {
		t.Errorf("expected 2 items preserved, got %d", len(items))
	}
}

func TestDeepMergeYAML_BooleanValues(t *testing.T) {
	base := map[string]interface{}{
		"enabled": true,
		"debug":   false,
	}
	overlay := map[string]interface{}{
		"enabled": false,
	}
	result := DeepMergeYAML(base, overlay)
	if result["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", result["enabled"])
	}
	if result["debug"] != false {
		t.Errorf("expected debug=false preserved, got %v", result["debug"])
	}
}

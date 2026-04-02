// Package reconciler provides YAML merge utilities for the tb-manage
// config reconciler. All functions are pure — no I/O, no k8s API calls.
package reconciler

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Merge combines existing file content with desired ConfigMap content.
// strategy: "merge" (deep merge YAML maps) or "replace" (return desired as-is).
// Returns the merged YAML string with 2-space indentation.
func Merge(existing, desired []byte, strategy string) ([]byte, error) {
	switch strategy {
	case "replace":
		return marshalOrPassthrough(desired)
	case "merge":
		return mergeYAMLBytes(existing, desired)
	default:
		return nil, fmt.Errorf("unknown merge strategy: %q (expected \"merge\" or \"replace\")", strategy)
	}
}

// marshalOrPassthrough parses and re-marshals YAML to normalize formatting,
// or returns it as-is if it's valid.
func marshalOrPassthrough(data []byte) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []byte("{}\n"), nil
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	return marshalYAML(m)
}

// mergeYAMLBytes unmarshals both inputs and deep merges them.
func mergeYAMLBytes(existing, desired []byte) ([]byte, error) {
	var base map[string]interface{}
	var overlay map[string]interface{}

	if len(bytes.TrimSpace(existing)) > 0 {
		if err := yaml.Unmarshal(existing, &base); err != nil {
			return nil, fmt.Errorf("invalid existing YAML: %w", err)
		}
	}
	if len(bytes.TrimSpace(desired)) > 0 {
		if err := yaml.Unmarshal(desired, &overlay); err != nil {
			return nil, fmt.Errorf("invalid desired YAML: %w", err)
		}
	}

	merged := DeepMergeYAML(base, overlay)
	return marshalYAML(merged)
}

// DeepMergeYAML merges two YAML documents represented as maps.
// The overlay takes precedence for scalar values.
// For maps: recursively merge. For slices: append unique items (no duplicates).
// Base keys not in overlay are preserved (merge is additive only).
func DeepMergeYAML(base, overlay map[string]interface{}) map[string]interface{} {
	if base == nil && overlay == nil {
		return map[string]interface{}{}
	}
	if base == nil {
		return copyMap(overlay)
	}
	if overlay == nil {
		return copyMap(base)
	}

	result := copyMap(base)

	for key, overlayVal := range overlay {
		baseVal, exists := result[key]
		if !exists {
			result[key] = overlayVal
			continue
		}

		// Both exist — merge based on type
		baseMap, baseIsMap := toMap(baseVal)
		overlayMap, overlayIsMap := toMap(overlayVal)

		if baseIsMap && overlayIsMap {
			result[key] = DeepMergeYAML(baseMap, overlayMap)
			continue
		}

		baseSlice, baseIsSlice := toSlice(baseVal)
		overlaySlice, overlayIsSlice := toSlice(overlayVal)

		if baseIsSlice && overlayIsSlice {
			result[key] = mergeSlices(baseSlice, overlaySlice)
			continue
		}

		// Type mismatch or both scalars — overlay wins
		result[key] = overlayVal
	}

	return result
}

// mergeSlices appends items from overlay that don't already exist in base.
// Uses fmt.Sprintf for comparison to handle any type.
func mergeSlices(base, overlay []interface{}) []interface{} {
	result := make([]interface{}, len(base))
	copy(result, base)

	existing := make(map[string]bool, len(base))
	for _, item := range base {
		existing[fmt.Sprintf("%v", item)] = true
	}

	for _, item := range overlay {
		key := fmt.Sprintf("%v", item)
		if !existing[key] {
			result = append(result, item)
			existing[key] = true
		}
	}

	return result
}

// toMap attempts to convert an interface{} to map[string]interface{}.
// yaml.v3 unmarshals maps as map[string]interface{}.
func toMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// toSlice attempts to convert an interface{} to []interface{}.
func toSlice(v interface{}) ([]interface{}, bool) {
	s, ok := v.([]interface{})
	return s, ok
}

// copyMap creates a shallow copy of a map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// marshalYAML marshals a map to YAML with 2-space indentation.
func marshalYAML(m map[string]interface{}) ([]byte, error) {
	if m == nil {
		return []byte("{}\n"), nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("YAML marshal error: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("YAML encoder close error: %w", err)
	}
	return buf.Bytes(), nil
}

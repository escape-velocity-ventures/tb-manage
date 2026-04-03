// Package reconciler provides ConfigMap-driven config reconciliation for tb-manage.
// It polls ConfigMaps with the tb.io/config-reconciler=true label and parses them
// into structured ReconcileTarget values for downstream file writing and service restarts.
package reconciler

import (
	"context"
	"log"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// LabelConfigReconciler is the label that marks ConfigMaps for reconciliation.
	LabelConfigReconciler = "tb.io/config-reconciler"

	// Annotation keys for ConfigMap metadata.
	AnnotationTargetPath     = "tb.io/target-path"
	AnnotationMergeStrategy  = "tb.io/merge-strategy"
	AnnotationNodeSelector   = "tb.io/node-selector"
	AnnotationRestartService = "tb.io/restart-service"
	AnnotationMaxConcurrent  = "tb.io/max-concurrent"

	// Default values.
	DefaultMergeStrategy = "merge"
	DefaultMaxConcurrent = 1
)

// ReconcileTarget represents a parsed ConfigMap that should be reconciled to the host filesystem.
type ReconcileTarget struct {
	ConfigMapName   string
	Namespace       string
	TargetPath      string            // from tb.io/target-path annotation
	MergeStrategy   string            // "merge" or "replace" from tb.io/merge-strategy
	NodeSelector    map[string]string // parsed from tb.io/node-selector
	RestartService  string            // from tb.io/restart-service
	MaxConcurrent   int               // from tb.io/max-concurrent (default 1)
	Data            map[string]string // ConfigMap .data
	ResourceVersion string            // for change detection
}

// ListTargets fetches ConfigMaps with the reconciler label and parses them into targets.
// Filters by node labels -- only returns targets where this node matches the selector.
func ListTargets(ctx context.Context, client kubernetes.Interface, namespace string, nodeLabels map[string]string) ([]ReconcileTarget, error) {
	cmList, err := client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: LabelConfigReconciler + "=true",
	})
	if err != nil {
		return nil, err
	}

	var targets []ReconcileTarget
	for _, cm := range cmList.Items {
		annotations := cm.Annotations

		targetPath := annotations[AnnotationTargetPath]
		if targetPath == "" {
			log.Printf("WARN: ConfigMap %s/%s has reconciler label but missing %s annotation, skipping",
				cm.Namespace, cm.Name, AnnotationTargetPath)
			continue
		}

		mergeStrategy := annotations[AnnotationMergeStrategy]
		if mergeStrategy == "" {
			mergeStrategy = DefaultMergeStrategy
		}

		nodeSelector := ParseNodeSelector(annotations[AnnotationNodeSelector])

		maxConcurrent := DefaultMaxConcurrent
		if v := annotations[AnnotationMaxConcurrent]; v != "" {
			parsed, err := strconv.Atoi(v)
			if err != nil || parsed < 1 {
				log.Printf("WARN: ConfigMap %s/%s has invalid %s=%q, defaulting to %d",
					cm.Namespace, cm.Name, AnnotationMaxConcurrent, v, DefaultMaxConcurrent)
				parsed = DefaultMaxConcurrent
			}
			maxConcurrent = parsed
		}

		target := ReconcileTarget{
			ConfigMapName:   cm.Name,
			Namespace:       cm.Namespace,
			TargetPath:      targetPath,
			MergeStrategy:   mergeStrategy,
			NodeSelector:    nodeSelector,
			RestartService:  annotations[AnnotationRestartService],
			MaxConcurrent:   maxConcurrent,
			Data:            cm.Data,
			ResourceVersion: cm.ResourceVersion,
		}

		if !MatchesNode(target, nodeLabels) {
			continue
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// ParseNodeSelector parses "key1=value1,key2=value2" into a map.
// Malformed entries (missing '=') are silently skipped.
func ParseNodeSelector(s string) map[string]string {
	result := make(map[string]string)
	if s == "" {
		return result
	}

	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			result[key] = value
		}
	}

	return result
}

// MatchesNode checks if a target's node selector matches the given node labels.
// An empty or nil selector matches all nodes.
func MatchesNode(target ReconcileTarget, nodeLabels map[string]string) bool {
	if len(target.NodeSelector) == 0 {
		return true
	}
	for k, v := range target.NodeSelector {
		if nodeLabels[k] != v {
			return false
		}
	}
	return true
}

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultExcludeNamespaces are skipped unless overridden.
var DefaultExcludeNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"local-path-storage",
}

// K8sScanner discovers Kubernetes cluster resources using client-go.
type K8sScanner struct {
	ExcludeNamespaces map[string]bool
}

// NewK8sScanner creates a K8sScanner with default exclusions.
func NewK8sScanner() *K8sScanner {
	return NewK8sScannerWithExclusions(DefaultExcludeNamespaces)
}

// NewK8sScannerWithExclusions creates a K8sScanner with custom namespace exclusions.
func NewK8sScannerWithExclusions(exclude []string) *K8sScanner {
	m := make(map[string]bool, len(exclude))
	for _, ns := range exclude {
		m[ns] = true
	}
	return &K8sScanner{ExcludeNamespaces: m}
}

func (s *K8sScanner) Name() string       { return "cluster" }
func (s *K8sScanner) Platforms() []string { return nil }

func (s *K8sScanner) Scan(ctx context.Context, _ CommandRunner) (json.RawMessage, error) {
	config, err := GetK8sConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s dynamic client: %w", err)
	}

	log := slog.Default().With("scanner", "k8s")

	result := ClusterScanResult{}

	// Cluster version
	if ver, err := clientset.Discovery().ServerVersion(); err == nil {
		result.Version = ver.GitVersion
	}

	// Detect provider
	result.Provider = "kubernetes"
	result.Name = detectClusterName(clientset, ctx)

	// Nodes
	result.Nodes, err = scanNodes(ctx, clientset)
	if err != nil {
		log.Warn("failed to scan nodes", "error", err)
	}

	// Detect k3s
	for _, n := range result.Nodes {
		if strings.Contains(strings.ToLower(n.Version), "k3s") {
			result.Provider = "k3s"
			break
		}
	}

	// Namespaces
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	for _, ns := range nsList.Items {
		if s.ExcludeNamespaces[ns.Name] {
			continue
		}
		nsResult, err := scanNamespace(ctx, clientset, ns)
		if err != nil {
			log.Warn("failed to scan namespace", "namespace", ns.Name, "error", err)
			continue
		}
		result.Namespaces = append(result.Namespaces, nsResult)
	}

	// Flux CD
	result.FluxKustomizations, result.FluxDetected = scanFlux(ctx, dynClient, log)

	return json.Marshal(result)
}

// GetK8sConfig returns in-cluster config or falls back to kubeconfig.
func GetK8sConfig() (*rest.Config, error) {
	// Try in-cluster first
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fall back to kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// detectClusterName tries to determine the cluster name.
func detectClusterName(clientset kubernetes.Interface, ctx context.Context) string {
	// Try to get it from kubeconfig context
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	if cfg, err := clientcmd.LoadFromFile(kubeconfig); err == nil && cfg.CurrentContext != "" {
		return cfg.CurrentContext
	}

	// Fall back to first node name prefix
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err == nil && len(nodes.Items) > 0 {
		return nodes.Items[0].Name
	}

	return "unknown"
}

func scanNodes(ctx context.Context, clientset kubernetes.Interface) ([]NodeScanResult, error) {
	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var nodes []NodeScanResult
	for _, node := range nodeList.Items {
		status := "Unknown"
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				if cond.Status == corev1.ConditionTrue {
					status = "Ready"
				} else {
					status = "NotReady"
				}
				break
			}
		}

		roles := extractRoles(node.Labels)

		var internalIP, externalIP string
		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalIP:
				internalIP = addr.Address
			case corev1.NodeExternalIP:
				externalIP = addr.Address
			}
		}

		nodes = append(nodes, NodeScanResult{
			Name:             node.Name,
			Status:           status,
			Roles:            roles,
			Version:          node.Status.NodeInfo.KubeletVersion,
			OS:               node.Status.NodeInfo.OperatingSystem,
			OSImage:          node.Status.NodeInfo.OSImage,
			Arch:             node.Status.NodeInfo.Architecture,
			CPUCores:         cpuCores(node.Status.Capacity),
			MemoryBytes:      memoryBytes(node.Status.Capacity),
			ContainerRuntime: node.Status.NodeInfo.ContainerRuntimeVersion,
			InternalIP:       internalIP,
			ExternalIP:       externalIP,
		})
	}
	return nodes, nil
}

func cpuCores(capacity corev1.ResourceList) int {
	if q, ok := capacity[corev1.ResourceCPU]; ok {
		return int(q.Value())
	}
	return 0
}

func memoryBytes(capacity corev1.ResourceList) int64 {
	if q, ok := capacity[corev1.ResourceMemory]; ok {
		return q.Value()
	}
	return 0
}

func extractRoles(labels map[string]string) []string {
	var roles []string
	for k, v := range labels {
		if strings.HasPrefix(k, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(k, "node-role.kubernetes.io/")
			if role == "" && v != "" {
				role = v
			}
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		roles = []string{"worker"}
	}
	return roles
}

func scanNamespace(ctx context.Context, clientset kubernetes.Interface, ns corev1.Namespace) (NamespaceScanResult, error) {
	nsName := ns.Name
	result := NamespaceScanResult{
		Name:   nsName,
		Labels: ns.Labels,
	}

	// Workloads
	result.Workloads = scanWorkloads(ctx, clientset, nsName)

	// Services
	result.Services = scanServices(ctx, clientset, nsName)

	// Ingresses
	result.Ingresses = scanIngresses(ctx, clientset, nsName)

	// ConfigMaps
	result.ConfigMaps = scanConfigMaps(ctx, clientset, nsName)

	// Secrets
	result.Secrets = scanSecrets(ctx, clientset, nsName)

	// PVCs
	result.PVCs = scanPVCs(ctx, clientset, nsName)

	// CronJobs
	result.CronJobs = scanCronJobs(ctx, clientset, nsName)

	// NetworkPolicies
	result.NetworkPolicies = scanNetworkPolicies(ctx, clientset, nsName)

	// PDBs
	result.PDBs = scanPDBs(ctx, clientset, nsName)

	return result, nil
}

func scanWorkloads(ctx context.Context, clientset kubernetes.Interface, ns string) []WorkloadScanResult {
	var workloads []WorkloadScanResult

	// Deployments
	deploys, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, d := range deploys.Items {
			w := deploymentToWorkload(d)
			workloads = append(workloads, w)
		}
	}

	// StatefulSets
	stss, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range stss.Items {
			w := statefulSetToWorkload(s)
			workloads = append(workloads, w)
		}
	}

	// DaemonSets
	dss, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, d := range dss.Items {
			w := daemonSetToWorkload(d)
			workloads = append(workloads, w)
		}
	}

	return workloads
}

func deploymentToWorkload(d appsv1.Deployment) WorkloadScanResult {
	w := WorkloadScanResult{
		Name:      d.Name,
		Namespace: d.Namespace,
		Kind:      "Deployment",
		Replicas:  d.Spec.Replicas,
	}
	if d.Status.ReadyReplicas > 0 {
		rr := d.Status.ReadyReplicas
		w.ReadyReplicas = &rr
	}
	if d.Status.AvailableReplicas > 0 {
		ar := d.Status.AvailableReplicas
		w.AvailableReplicas = &ar
	}
	if d.Spec.Strategy.Type != "" {
		w.Strategy = string(d.Spec.Strategy.Type)
	}
	w.Containers = extractContainers(d.Spec.Template.Spec.Containers)
	w.Requests, w.Limits = aggregateResources(d.Spec.Template.Spec.Containers)
	return w
}

func statefulSetToWorkload(s appsv1.StatefulSet) WorkloadScanResult {
	w := WorkloadScanResult{
		Name:      s.Name,
		Namespace: s.Namespace,
		Kind:      "StatefulSet",
		Replicas:  s.Spec.Replicas,
	}
	if s.Status.ReadyReplicas > 0 {
		rr := s.Status.ReadyReplicas
		w.ReadyReplicas = &rr
	}
	w.Containers = extractContainers(s.Spec.Template.Spec.Containers)
	w.Requests, w.Limits = aggregateResources(s.Spec.Template.Spec.Containers)
	return w
}

func daemonSetToWorkload(d appsv1.DaemonSet) WorkloadScanResult {
	w := WorkloadScanResult{
		Name:      d.Name,
		Namespace: d.Namespace,
		Kind:      "DaemonSet",
	}
	dns := d.Status.DesiredNumberScheduled
	w.DesiredNumberScheduled = &dns
	nr := d.Status.NumberReady
	w.NumberReady = &nr
	w.Containers = extractContainers(d.Spec.Template.Spec.Containers)
	w.Requests, w.Limits = aggregateResources(d.Spec.Template.Spec.Containers)
	return w
}

func extractContainers(containers []corev1.Container) []ContainerInfoK8s {
	var result []ContainerInfoK8s
	for _, c := range containers {
		result = append(result, ContainerInfoK8s{
			Name:  c.Name,
			Image: c.Image,
		})
	}
	return result
}

func aggregateResources(containers []corev1.Container) (*ResourceRequirements, *ResourceRequirements) {
	var reqCPU, reqMem, limCPU, limMem int64
	hasReq, hasLim := false, false

	for _, c := range containers {
		if cpu := c.Resources.Requests.Cpu(); cpu != nil && !cpu.IsZero() {
			reqCPU += cpu.MilliValue()
			hasReq = true
		}
		if mem := c.Resources.Requests.Memory(); mem != nil && !mem.IsZero() {
			reqMem += mem.Value()
			hasReq = true
		}
		if cpu := c.Resources.Limits.Cpu(); cpu != nil && !cpu.IsZero() {
			limCPU += cpu.MilliValue()
			hasLim = true
		}
		if mem := c.Resources.Limits.Memory(); mem != nil && !mem.IsZero() {
			limMem += mem.Value()
			hasLim = true
		}
	}

	var req, lim *ResourceRequirements
	if hasReq {
		req = &ResourceRequirements{CPUMillicores: reqCPU, MemoryBytes: reqMem}
	}
	if hasLim {
		lim = &ResourceRequirements{CPUMillicores: limCPU, MemoryBytes: limMem}
	}
	return req, lim
}

func scanServices(ctx context.Context, clientset kubernetes.Interface, ns string) []K8sServiceScanResult {
	var services []K8sServiceScanResult
	svcList, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, svc := range svcList.Items {
		s := K8sServiceScanResult{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Type:      string(svc.Spec.Type),
			ClusterIP: svc.Spec.ClusterIP,
			Selector:  svc.Spec.Selector,
		}
		for _, p := range svc.Spec.Ports {
			sp := ServicePort{
				Name:       p.Name,
				Protocol:   string(p.Protocol),
				Port:       p.Port,
				TargetPort: p.TargetPort.String(),
			}
			if p.NodePort > 0 {
				sp.NodePort = p.NodePort
			}
			s.Ports = append(s.Ports, sp)
		}
		if len(svc.Spec.ExternalIPs) > 0 {
			s.ExternalIPs = svc.Spec.ExternalIPs
		}
		services = append(services, s)
	}
	return services
}

func scanIngresses(ctx context.Context, clientset kubernetes.Interface, ns string) []IngressScanResult {
	var ingresses []IngressScanResult
	ingList, err := clientset.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, ing := range ingList.Items {
		i := IngressScanResult{
			Name:      ing.Name,
			Namespace: ing.Namespace,
		}
		if ing.Spec.IngressClassName != nil {
			i.IngressClass = *ing.Spec.IngressClassName
		}
		for _, rule := range ing.Spec.Rules {
			r := IngressRule{Host: rule.Host}
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					p := IngressPath{Path: path.Path}
					if path.Backend.Service != nil {
						p.Backend = path.Backend.Service.Name
						if path.Backend.Service.Port.Number > 0 {
							p.Port = strconv.Itoa(int(path.Backend.Service.Port.Number))
						} else {
							p.Port = path.Backend.Service.Port.Name
						}
					}
					r.Paths = append(r.Paths, p)
				}
			}
			i.Rules = append(i.Rules, r)
		}
		for _, tls := range ing.Spec.TLS {
			i.TLS = append(i.TLS, IngressTLS{
				Hosts:      tls.Hosts,
				SecretName: tls.SecretName,
			})
		}
		ingresses = append(ingresses, i)
	}
	return ingresses
}

func scanConfigMaps(ctx context.Context, clientset kubernetes.Interface, ns string) []ConfigMapScanResult {
	var cms []ConfigMapScanResult
	cmList, err := clientset.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, cm := range cmList.Items {
		// Skip auto-generated configmaps
		if strings.HasPrefix(cm.Name, "kube-root-ca") {
			continue
		}
		keys := make([]string, 0, len(cm.Data))
		for k := range cm.Data {
			keys = append(keys, k)
		}
		cms = append(cms, ConfigMapScanResult{
			Name:      cm.Name,
			Namespace: cm.Namespace,
			DataKeys:  keys,
		})
	}
	return cms
}

func scanSecrets(ctx context.Context, clientset kubernetes.Interface, ns string) []SecretScanResult {
	var secrets []SecretScanResult
	secretList, err := clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, s := range secretList.Items {
		// Skip service account tokens
		if s.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		keys := make([]string, 0, len(s.Data))
		for k := range s.Data {
			keys = append(keys, k)
		}
		secrets = append(secrets, SecretScanResult{
			Name:      s.Name,
			Namespace: s.Namespace,
			Type:      string(s.Type),
			DataKeys:  keys,
		})
	}
	return secrets
}

func scanPVCs(ctx context.Context, clientset kubernetes.Interface, ns string) []PVCScanResult {
	var pvcs []PVCScanResult
	pvcList, err := clientset.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, pvc := range pvcList.Items {
		p := PVCScanResult{
			Name:      pvc.Name,
			Namespace: pvc.Namespace,
			Status:    string(pvc.Status.Phase),
		}
		if pvc.Spec.StorageClassName != nil {
			p.StorageClass = *pvc.Spec.StorageClassName
		}
		for _, am := range pvc.Spec.AccessModes {
			p.AccessModes = append(p.AccessModes, string(am))
		}
		if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			p.Capacity = cap.String()
		}
		pvcs = append(pvcs, p)
	}
	return pvcs
}

func scanCronJobs(ctx context.Context, clientset kubernetes.Interface, ns string) []CronJobScanResult {
	var cronJobs []CronJobScanResult
	cjList, err := clientset.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, cj := range cjList.Items {
		c := CronJobScanResult{
			Name:      cj.Name,
			Namespace: cj.Namespace,
			Schedule:  cj.Spec.Schedule,
			Suspend:   cj.Spec.Suspend != nil && *cj.Spec.Suspend,
		}
		if cj.Status.LastScheduleTime != nil {
			t := cj.Status.LastScheduleTime.Format("2006-01-02T15:04:05Z")
			c.LastScheduleTime = &t
		}
		cronJobs = append(cronJobs, c)
	}
	return cronJobs
}

func scanNetworkPolicies(ctx context.Context, clientset kubernetes.Interface, ns string) []NetworkPolicyScanResult {
	var nps []NetworkPolicyScanResult
	npList, err := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, np := range npList.Items {
		pTypes := make([]string, len(np.Spec.PolicyTypes))
		for i, pt := range np.Spec.PolicyTypes {
			pTypes[i] = string(pt)
		}
		nps = append(nps, NetworkPolicyScanResult{
			Name:        np.Name,
			Namespace:   np.Namespace,
			PodSelector: labelSelectorToMap(np.Spec.PodSelector),
			PolicyTypes: pTypes,
		})
	}
	return nps
}

func scanPDBs(ctx context.Context, clientset kubernetes.Interface, ns string) []PDBScanResult {
	var pdbs []PDBScanResult
	pdbList, err := clientset.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, pdb := range pdbList.Items {
		p := PDBScanResult{
			Name:      pdb.Name,
			Namespace: pdb.Namespace,
		}
		if pdb.Spec.MinAvailable != nil {
			s := pdb.Spec.MinAvailable.String()
			p.MinAvailable = &s
		}
		if pdb.Spec.MaxUnavailable != nil {
			s := pdb.Spec.MaxUnavailable.String()
			p.MaxUnavailable = &s
		}
		if pdb.Spec.Selector != nil {
			p.Selector = labelSelectorToMap(*pdb.Spec.Selector)
		}
		pdbs = append(pdbs, p)
	}
	return pdbs
}

func labelSelectorToMap(sel metav1.LabelSelector) map[string]interface{} {
	result := map[string]interface{}{
		"matchLabels": sel.MatchLabels,
	}
	if len(sel.MatchExpressions) > 0 {
		exprs := make([]map[string]interface{}, len(sel.MatchExpressions))
		for i, e := range sel.MatchExpressions {
			exprs[i] = map[string]interface{}{
				"key":      e.Key,
				"operator": string(e.Operator),
				"values":   e.Values,
			}
		}
		result["matchExpressions"] = exprs
	}
	return result
}

func scanFlux(ctx context.Context, dynClient dynamic.Interface, log *slog.Logger) ([]FluxKustomizationResult, bool) {
	gvr := schema.GroupVersionResource{
		Group:    "kustomize.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "kustomizations",
	}

	list, err := dynClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Flux not installed — not an error
		log.Debug("flux CRD not found", "error", err)
		return nil, false
	}

	if len(list.Items) == 0 {
		return nil, true
	}

	var kustomizations []FluxKustomizationResult
	for _, item := range list.Items {
		spec, _ := item.Object["spec"].(map[string]interface{})
		if spec == nil {
			continue
		}

		k := FluxKustomizationResult{
			Name: item.GetName(),
		}
		if p, ok := spec["path"].(string); ok {
			k.Path = p
		}
		if tn, ok := spec["targetNamespace"].(string); ok {
			k.TargetNamespace = tn
		}
		if sr, ok := spec["sourceRef"].(map[string]interface{}); ok {
			k.SourceRef = sr
		}
		if iv, ok := spec["interval"].(string); ok {
			k.Interval = iv
		}
		if pr, ok := spec["prune"].(bool); ok {
			k.Prune = pr
		}

		kustomizations = append(kustomizations, k)
	}

	return kustomizations, true
}

// Ensure unused imports don't cause build errors — these are used above.
var (
	_ = (*appsv1.Deployment)(nil)
	_ = (*batchv1.CronJob)(nil)
	_ = (*networkingv1.Ingress)(nil)
	_ = (*policyv1.PodDisruptionBudget)(nil)
)

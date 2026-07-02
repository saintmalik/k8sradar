package providers

import "github.com/abdulmalik/k8sradar/core/models"

func standardK8sCatalog(extra ...models.ComponentDefinition) []models.ComponentDefinition {
	base := []models.ComponentDefinition{
		{Name: "kubernetes", Label: "Kubernetes (control plane)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
		{Name: "kubelet", Label: "Kubelet", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
		{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		{Name: "kube-proxy", Label: "kube-proxy", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
	}
	return append(base, extra...)
}

func newManifest(id models.Provider, label, manifestDir, manifestName string, catalog []models.ComponentDefinition, nodeOS []NodeOSOption) Provider {
	return &manifestProvider{
		id:           id,
		label:        label,
		manifestPath: manifestPath(manifestDir, manifestName),
		catalog:      catalog,
		nodeOS:       nodeOS,
	}
}

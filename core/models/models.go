package models

import "time"

type Provider string

const (
	ProviderEKS       Provider = "eks"
	ProviderGKE       Provider = "gke"
	ProviderAKS       Provider = "aks"
	ProviderOKE       Provider = "oke"
	ProviderDOKS      Provider = "doks"
	ProviderLKE       Provider = "lke"
	ProviderIKS       Provider = "iks"
	ProviderScaleway  Provider = "scaleway"
	ProviderCivo      Provider = "civo"
	ProviderOpenShift Provider = "openshift"
	ProviderTanzu     Provider = "tanzu"
	ProviderRKE2      Provider = "rke2"
	ProviderK3s       Provider = "k3s"
	ProviderMicroK8s  Provider = "microk8s"
	ProviderTalos     Provider = "talos"
	ProviderKind      Provider = "kind"
	ProviderMinikube  Provider = "minikube"
	ProviderUpstream  Provider = "upstream"
)

func (p Provider) Label() string {
	switch p {
	case ProviderEKS:
		return "Amazon EKS"
	case ProviderGKE:
		return "Google GKE"
	case ProviderAKS:
		return "Azure AKS"
	case ProviderOKE:
		return "Oracle OKE"
	case ProviderDOKS:
		return "DigitalOcean DOKS"
	case ProviderLKE:
		return "Akamai Linode LKE"
	case ProviderIKS:
		return "IBM Cloud IKS"
	case ProviderScaleway:
		return "Scaleway Kapsule"
	case ProviderCivo:
		return "Civo Kubernetes"
	case ProviderOpenShift:
		return "Red Hat OpenShift"
	case ProviderTanzu:
		return "VMware Tanzu"
	case ProviderRKE2:
		return "Rancher RKE2"
	case ProviderK3s:
		return "k3s"
	case ProviderMicroK8s:
		return "MicroK8s"
	case ProviderTalos:
		return "Talos Linux"
	case ProviderKind:
		return "kind (local dev)"
	case ProviderMinikube:
		return "minikube (local dev)"
	case ProviderUpstream:
		return "Self-managed (kubeadm / vanilla)"
	default:
		return string(p)
	}
}

func AllProviders() []Provider {
	return []Provider{
		ProviderEKS, ProviderGKE, ProviderAKS,
		ProviderOKE, ProviderDOKS, ProviderLKE,
		ProviderIKS, ProviderScaleway, ProviderCivo,
		ProviderOpenShift, ProviderTanzu, ProviderRKE2,
		ProviderK3s, ProviderMicroK8s, ProviderTalos,
		ProviderKind, ProviderMinikube,
		ProviderUpstream,
	}
}

type ComponentVersion struct {
	Name    string
	Version string
}

type ClusterInput struct {
	Provider   Provider
	K8sVersion string
	NodeOS     string
	Components []ComponentVersion
	Assets     []Asset
}

// Asset represents a generic software asset scanned by OSV package/ecosystem/version.
// It sits alongside Kubernetes provider components in a ClusterInput.
type Asset struct {
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Package   string `json:"package" yaml:"package"`
	Ecosystem string `json:"ecosystem" yaml:"ecosystem"`
	Version   string `json:"version" yaml:"version"`
}

type ComponentDefinition struct {
	Name         string
	Label        string
	OSVPackage   string
	OSVEcosystem string
}

type EnrichedCVE struct {
	ID                string
	Description       string
	CVSSScore         float64
	CVSSVector        string
	EPSSScore         float64
	EPSSPercentile    float64
	InKEV             bool
	RemoteExploitable bool
	Component         string
	InstalledVersion  string
	FixedIn           string
	Source            string
	Severity          string
	// Asset is non-empty when the finding came from a generic Asset rather than a
	// Kubernetes provider catalog component.
	Asset string `json:"asset,omitempty" yaml:"asset,omitempty"`
}

type OSVQuery struct {
	Package   string
	Ecosystem string
	Version   string
	Component string
	// Asset is the display name of the source asset when this query was built
	// from a generic Asset rather than a Kubernetes provider catalog component.
	Asset string `json:"asset,omitempty" yaml:"asset,omitempty"`
}

// ReportSummary holds aggregate counts and gate status for a scan.
type ReportSummary struct {
	Total             int
	SeverityCounts    map[string]int
	KEVCount          int
	MaxEPSS           float64
	MaxEPSSPercentile float64
	Gate              string
	GateBreached      bool
}

// ScanReport is a serializable scan result suitable for JSON/SARIF/HTML/TXT outputs.
type ScanReport struct {
	ScannedAt time.Time     `json:"scanned_at" yaml:"scanned_at"`
	Input     ClusterInput  `json:"input" yaml:"input"`
	Results   []EnrichedCVE `json:"results" yaml:"results"`
	Summary   ReportSummary `json:"summary" yaml:"summary"`
}

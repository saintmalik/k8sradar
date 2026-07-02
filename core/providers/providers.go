package providers

import "github.com/abdulmalik/k8sradar/core/models"

func newEKS(manifestDir string) Provider {
	return newManifest(
		models.ProviderEKS, "Amazon EKS", manifestDir, "eks",
		append(standardK8sCatalog(), models.ComponentDefinition{
			Name: "vpc-cni", Label: "VPC CNI (aws-node)",
			OSVPackage: "github.com/aws/amazon-vpc-cni-k8s", OSVEcosystem: "Go",
		}),
		[]NodeOSOption{
			{Value: "al2023", Label: "Amazon Linux 2023"},
			{Value: "al2", Label: "Amazon Linux 2"},
			{Value: "bottlerocket", Label: "Bottlerocket"},
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newGKE(manifestDir string) Provider {
	return newManifest(
		models.ProviderGKE, "Google GKE", manifestDir, "gke",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "cos", Label: "Container-Optimized OS"},
			{Value: "ubuntu", Label: "Ubuntu"},
			{Value: "windows", Label: "Windows"},
		},
	)
}

func newAKS(manifestDir string) Provider {
	return newManifest(
		models.ProviderAKS, "Azure AKS", manifestDir, "aks",
		append(standardK8sCatalog(), models.ComponentDefinition{
			Name: "azure-cns", Label: "Azure CNS",
			OSVPackage: "github.com/Azure/azure-container-networking", OSVEcosystem: "Go",
		}),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
			{Value: "mariner", Label: "Azure Linux (Mariner)"},
			{Value: "windows", Label: "Windows"},
		},
	)
}

func newOKE(manifestDir string) Provider {
	return newManifest(
		models.ProviderOKE, "Oracle OKE", manifestDir, "oke",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "oke", Label: "Oracle Linux (OKE image)"},
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newDOKS(manifestDir string) Provider {
	return newManifest(
		models.ProviderDOKS, "DigitalOcean DOKS", manifestDir, "doks",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newLKE(manifestDir string) Provider {
	return newManifest(
		models.ProviderLKE, "Akamai Linode LKE", manifestDir, "lke",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newIKS(manifestDir string) Provider {
	return newManifest(
		models.ProviderIKS, "IBM Cloud IKS", manifestDir, "iks",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
			{Value: "rhel", Label: "RHEL / RHCOS"},
		},
	)
}

func newScaleway(manifestDir string) Provider {
	return newManifest(
		models.ProviderScaleway, "Scaleway Kapsule", manifestDir, "scaleway",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newCivo(manifestDir string) Provider {
	return newManifest(
		models.ProviderCivo, "Civo Kubernetes", manifestDir, "civo",
		standardK8sCatalog(),
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newOpenShift(manifestDir string) Provider {
	return newManifest(
		models.ProviderOpenShift, "Red Hat OpenShift", manifestDir, "openshift",
		append(standardK8sCatalog(),
			models.ComponentDefinition{Name: "etcd", Label: "etcd", OSVPackage: "go.etcd.io/etcd", OSVEcosystem: "Go"},
			models.ComponentDefinition{Name: "openshift", Label: "OpenShift", OSVPackage: "github.com/openshift/kubernetes", OSVEcosystem: "Go"},
		),
		[]NodeOSOption{
			{Value: "rhel", Label: "RHEL CoreOS"},
		},
	)
}

func newTanzu(manifestDir string) Provider {
	return newManifest(
		models.ProviderTanzu, "VMware Tanzu", manifestDir, "tanzu",
		append(standardK8sCatalog(),
			models.ComponentDefinition{Name: "etcd", Label: "etcd", OSVPackage: "go.etcd.io/etcd", OSVEcosystem: "Go"},
			models.ComponentDefinition{Name: "contour", Label: "Contour", OSVPackage: "github.com/projectcontour/contour", OSVEcosystem: "Go"},
		),
		[]NodeOSOption{
			{Value: "photon", Label: "Photon OS"},
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newRKE2(manifestDir string) Provider {
	return newManifest(
		models.ProviderRKE2, "Rancher RKE2", manifestDir, "rke2",
		[]models.ComponentDefinition{
			{Name: "rke2", Label: "RKE2", OSVPackage: "github.com/rancher/rke2", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (embedded)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
			{Name: "etcd", Label: "etcd", OSVPackage: "go.etcd.io/etcd", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "rhel", Label: "RHEL / Rocky / Alma"},
			{Value: "ubuntu", Label: "Ubuntu"},
		},
	)
}

func newK3s(manifestDir string) Provider {
	return newManifest(
		models.ProviderK3s, "k3s", manifestDir, "k3s",
		[]models.ComponentDefinition{
			{Name: "k3s", Label: "k3s", OSVPackage: "github.com/k3s-io/k3s", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (embedded)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "generic", Label: "Generic Linux"},
		},
	)
}

func newMicroK8s(manifestDir string) Provider {
	return newManifest(
		models.ProviderMicroK8s, "MicroK8s", manifestDir, "microk8s",
		[]models.ComponentDefinition{
			{Name: "microk8s", Label: "MicroK8s", OSVPackage: "github.com/canonical/microk8s", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (embedded)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "ubuntu", Label: "Ubuntu (snap)"},
		},
	)
}

func newTalos(manifestDir string) Provider {
	return newManifest(
		models.ProviderTalos, "Talos Linux", manifestDir, "talos",
		[]models.ComponentDefinition{
			{Name: "talos", Label: "Talos", OSVPackage: "github.com/siderolabs/talos", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (embedded)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "talos", Label: "Talos (immutable OS)"},
		},
	)
}

func newKind(manifestDir string) Provider {
	return newManifest(
		models.ProviderKind, "kind (local dev)", manifestDir, "kind",
		[]models.ComponentDefinition{
			{Name: "kind", Label: "kind", OSVPackage: "github.com/kubernetes-sigs/kind", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (node image)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "node-image", Label: "kindest/node image"},
		},
	)
}

func newMinikube(manifestDir string) Provider {
	return newManifest(
		models.ProviderMinikube, "minikube (local dev)", manifestDir, "minikube",
		[]models.ComponentDefinition{
			{Name: "minikube", Label: "minikube", OSVPackage: "github.com/kubernetes/minikube", OSVEcosystem: "Go"},
			{Name: "kubernetes", Label: "Kubernetes (embedded)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
		},
		[]NodeOSOption{
			{Value: "docker", Label: "Docker driver"},
			{Value: "generic", Label: "Other driver"},
		},
	)
}

func newUpstream(_ string) Provider {
	return &manifestProvider{
		id:           models.ProviderUpstream,
		label:        "Self-managed (kubeadm / vanilla)",
		manifestPath: "",
		catalog: []models.ComponentDefinition{
			{Name: "kubernetes", Label: "Kubernetes (control plane)", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "kubelet", Label: "Kubelet", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "etcd", Label: "etcd", OSVPackage: "go.etcd.io/etcd", OSVEcosystem: "Go"},
			{Name: "coredns", Label: "CoreDNS", OSVPackage: "github.com/coredns/coredns", OSVEcosystem: "Go"},
			{Name: "kube-proxy", Label: "kube-proxy", OSVPackage: "k8s.io/kubernetes", OSVEcosystem: "Go"},
			{Name: "containerd", Label: "containerd", OSVPackage: "github.com/containerd/containerd", OSVEcosystem: "Go"},
		},
		nodeOS: []NodeOSOption{
			{Value: "generic", Label: "Generic Linux"},
		},
	}
}

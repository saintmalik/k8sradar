package input

import (
	"testing"

	"github.com/abdulmalik/k8sradar/core/models"
)

func TestResolveFileOnly(t *testing.T) {
	file := StackConfig{
		Provider:   "eks",
		K8sVersion: "1.30",
		NodeOS:     "al2023",
		Components: []models.ComponentVersion{{Name: "kubernetes", Version: "1.30.0"}},
	}
	got := Resolve(file, Flags{})
	if got.Provider != "eks" || got.K8sVersion != "1.30" || got.NodeOS != "al2023" {
		t.Errorf("got %+v", got)
	}
}

func TestResolveFlagOverridesFile(t *testing.T) {
	file := StackConfig{Provider: "eks", K8sVersion: "1.30"}
	flags := Flags{
		Provider:   "gke",
		K8sVersion: "1.31",
		Changed:    map[string]bool{"provider": true, "k8s-version": true},
	}
	got := Resolve(file, flags)
	if got.Provider != "gke" || got.K8sVersion != "1.31" {
		t.Errorf("got %+v", got)
	}
}

func TestResolveComponentsMerged(t *testing.T) {
	file := StackConfig{
		Components: []models.ComponentVersion{
			{Name: "kubernetes", Version: "1.30.0"},
			{Name: "coredns", Version: "1.10.0"},
		},
	}
	flags := Flags{
		Components: []models.ComponentVersion{{Name: "kubernetes", Version: "1.31.0"}},
		Changed:    map[string]bool{"component": true},
	}
	got := Resolve(file, flags)
	if len(got.Components) != 2 {
		t.Fatalf("expected 2 components, got %d: %+v", len(got.Components), got.Components)
	}
	for _, c := range got.Components {
		if c.Name == "kubernetes" && c.Version != "1.31.0" {
			t.Errorf("kubernetes not overridden: %+v", c)
		}
	}
}

func TestResolveAssetsAppended(t *testing.T) {
	file := StackConfig{Assets: []models.Asset{{Package: "nginx", Ecosystem: "Debian", Version: "1.25.0"}}}
	flags := Flags{
		Assets:  []models.Asset{{Package: "openssl", Ecosystem: "Alpine", Version: "3.1.0"}},
		Changed: map[string]bool{"asset": true},
	}
	got := Resolve(file, flags)
	if len(got.Assets) != 2 {
		t.Errorf("expected 2 assets, got %+v", got.Assets)
	}
}

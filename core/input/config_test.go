package input

import (
	"strings"
	"testing"

	"github.com/abdulmalik/k8sradar/core/models"
)

func TestParseStackYAML(t *testing.T) {
	data := `
provider: eks
k8s_version: "1.31"
node_os: al2023
components:
  - name: kubernetes
    version: "1.31.2"
assets:
  - name: nginx
    package: nginx
    ecosystem: Debian
    version: "1.25.3"
`
	cfg, err := ParseStack([]byte(data))
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	if cfg.Provider != "eks" {
		t.Errorf("provider: got %q, want eks", cfg.Provider)
	}
	if cfg.K8sVersion != "1.31" {
		t.Errorf("k8s_version: got %q, want 1.31", cfg.K8sVersion)
	}
	if cfg.NodeOS != "al2023" {
		t.Errorf("node_os: got %q, want al2023", cfg.NodeOS)
	}
	if len(cfg.Components) != 1 || cfg.Components[0].Name != "kubernetes" {
		t.Errorf("components: got %+v", cfg.Components)
	}
	if len(cfg.Assets) != 1 || cfg.Assets[0].Name != "nginx" {
		t.Errorf("assets: got %+v", cfg.Assets)
	}
}

func TestParseComponentFlag(t *testing.T) {
	c, err := ParseComponentFlag("kubernetes=1.31.2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Name != "kubernetes" || c.Version != "1.31.2" {
		t.Errorf("got %+v", c)
	}
}

func TestParseAssetFlagSlash(t *testing.T) {
	a, err := ParseAssetFlag("go/k8s.io/kubernetes@1.31.2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := models.Asset{Name: "kubernetes", Package: "k8s.io/kubernetes", Ecosystem: "go", Version: "1.31.2"}
	if a != want {
		t.Errorf("got %+v, want %+v", a, want)
	}
}

func TestParseAssetFlagPURL(t *testing.T) {
	a, err := ParseAssetFlag("pkg:go/k8s.io/kubernetes@1.31.2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := models.Asset{Name: "kubernetes", Package: "k8s.io/kubernetes", Ecosystem: "go", Version: "1.31.2"}
	if a != want {
		t.Errorf("got %+v, want %+v", a, want)
	}
}

func TestParseAssetFlagInvalid(t *testing.T) {
	for _, raw := range []string{"", "no-at-sign", "only/package"} {
		_, err := ParseAssetFlag(raw)
		if err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestParseStackJSON(t *testing.T) {
	data := `{"provider":"gke","k8s_version":"1.30","assets":[{"package":"nginx","ecosystem":"Debian","version":"1.25.3"}]}`
	cfg, err := ParseStack([]byte(data))
	if err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if cfg.Provider != "gke" || cfg.K8sVersion != "1.30" {
		t.Errorf("got %+v", cfg)
	}
	if len(cfg.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(cfg.Assets))
	}
}

func TestParsePURLWithNamespace(t *testing.T) {
	a, err := ParseAssetFlag("pkg:npm/@angular/core@17.0.0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.Package != "@angular/core" {
		t.Errorf("package: got %q", a.Package)
	}
	if !strings.Contains(a.Name, "core") {
		t.Errorf("name should contain core: got %q", a.Name)
	}
}

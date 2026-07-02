package providers

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abdulmalik/k8sradar/core/models"
	"gopkg.in/yaml.v3"
)

//go:embed manifests/*.yaml
var manifestsFS embed.FS

type Provider interface {
	ID() models.Provider
	Label() string
	DefaultNodeOS() string
	DefaultComponents(ctx context.Context, k8sVersion, nodeOS string) ([]models.ComponentVersion, error)
	Catalog() []models.ComponentDefinition
	NodeOSOptions() []NodeOSOption
}

type NodeOSOption struct {
	Value string
	Label string
}

type manifest struct {
	Versions map[string]versionEntry `yaml:"versions"`
}

type versionEntry struct {
	Components map[string]string `yaml:"components"`
}

type manifestProvider struct {
	id          models.Provider
	label       string
	manifestPath string
	catalog     []models.ComponentDefinition
	nodeOS      []NodeOSOption
}

func (p *manifestProvider) ID() models.Provider { return p.id }
func (p *manifestProvider) Label() string       { return p.label }

func (p *manifestProvider) NodeOSOptions() []NodeOSOption { return p.nodeOS }

func (p *manifestProvider) DefaultNodeOS() string {
	if len(p.nodeOS) == 0 {
		return ""
	}
	return p.nodeOS[0].Value
}

func (p *manifestProvider) Catalog() []models.ComponentDefinition { return p.catalog }

func (p *manifestProvider) DefaultComponents(_ context.Context, k8sVersion, _ string) ([]models.ComponentVersion, error) {
	if p.manifestPath == "" {
		comps := defaultFromCatalog(p.catalog)
		for i := range comps {
			if comps[i].Name == "kubernetes" && k8sVersion != "" {
				comps[i].Version = normalizeVersion(k8sVersion)
			}
		}
		return comps, nil
	}

	data, err := readManifest(p.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	key := normalizeVersion(k8sVersion)
	entry, ok := m.Versions[key]
	if !ok {
		// try minor match e.g. 1.29 from 1.29.4
		parts := strings.Split(key, ".")
		if len(parts) >= 2 {
			minor := parts[0] + "." + parts[1]
			entry, ok = m.Versions[minor]
		}
	}
	if !ok {
		return defaultFromCatalog(p.catalog), nil
	}

	var out []models.ComponentVersion
	for _, def := range p.catalog {
		v := entry.Components[def.Name]
		out = append(out, models.ComponentVersion{Name: def.Name, Version: v})
	}
	return out, nil
}

func defaultFromCatalog(catalog []models.ComponentDefinition) []models.ComponentVersion {
	out := make([]models.ComponentVersion, len(catalog))
	for i, c := range catalog {
		out[i] = models.ComponentVersion{Name: c.Name, Version: ""}
	}
	return out
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	return v
}

type Registry struct {
	byID map[models.Provider]Provider
}

func NewRegistry(manifestDir string) *Registry {
	r := &Registry{byID: make(map[models.Provider]Provider)}
	for _, p := range []Provider{
		newEKS(manifestDir),
		newGKE(manifestDir),
		newAKS(manifestDir),
		newOKE(manifestDir),
		newDOKS(manifestDir),
		newLKE(manifestDir),
		newIKS(manifestDir),
		newScaleway(manifestDir),
		newCivo(manifestDir),
		newOpenShift(manifestDir),
		newTanzu(manifestDir),
		newRKE2(manifestDir),
		newK3s(manifestDir),
		newMicroK8s(manifestDir),
		newTalos(manifestDir),
		newKind(manifestDir),
		newMinikube(manifestDir),
		newUpstream(manifestDir),
	} {
		r.byID[p.ID()] = p
	}
	return r
}

func (r *Registry) Get(id models.Provider) (Provider, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", id)
	}
	return p, nil
}

func (r *Registry) All() []Provider {
	out := make([]Provider, 0, len(r.byID))
	for _, id := range models.AllProviders() {
		if p, ok := r.byID[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func manifestPath(dir, name string) string {
	return filepath.Join(dir, name+".yaml")
}

// readManifest tries the requested path first, then falls back to the embedded
// manifests shipped with the core module. This lets the CLI work from any
// working directory without distributing files alongside the binary.
func readManifest(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	}
	base := filepath.Base(path)
	return manifestsFS.ReadFile("manifests/" + base)
}

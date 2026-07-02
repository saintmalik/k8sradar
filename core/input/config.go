package input

import (
	"fmt"
	"strings"

	"github.com/abdulmalik/k8sradar/core/models"
	"gopkg.in/yaml.v3"
)

// StackConfig is the YAML/JSON shape accepted from --config files or stdin.
type StackConfig struct {
	Provider   string                 `json:"provider" yaml:"provider"`
	K8sVersion string                 `json:"k8s_version" yaml:"k8s_version"`
	NodeOS     string                 `json:"node_os" yaml:"node_os"`
	Components []models.ComponentVersion `json:"components" yaml:"components"`
	Assets     []models.Asset         `json:"assets" yaml:"assets"`
}

// ParseStack parses YAML or JSON bytes into a StackConfig.
// yaml.v3 transparently handles JSON as well.
func ParseStack(data []byte) (StackConfig, error) {
	var cfg StackConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return StackConfig{}, fmt.Errorf("parse stack config: %w", err)
	}
	return cfg, nil
}

// ParseComponentFlag parses a CLI component override like "kubernetes=1.31.2".
func ParseComponentFlag(s string) (models.ComponentVersion, error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return models.ComponentVersion{}, fmt.Errorf("component must be name=version: %q", s)
	}
	return models.ComponentVersion{
		Name:    strings.TrimSpace(parts[0]),
		Version: strings.TrimSpace(parts[1]),
	}, nil
}

// ParseAssetFlag parses a CLI asset like "ecosystem/package@version" or
// "pkg:ecosystem/package@version".
func ParseAssetFlag(s string) (models.Asset, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return models.Asset{}, fmt.Errorf("asset cannot be empty")
	}

	if strings.HasPrefix(s, "pkg:") {
		return parsePURL(s)
	}
	return parseSlashAsset(s)
}

// parseSlashAsset accepts "ecosystem/package@version".
func parseSlashAsset(s string) (models.Asset, error) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return models.Asset{}, fmt.Errorf("asset must be ecosystem/package@version: %q", s)
	}
	version := strings.TrimSpace(s[at+1:])
	left := strings.TrimSpace(s[:at])
	ec, pk, ok := strings.Cut(left, "/")
	if !ok {
		return models.Asset{}, fmt.Errorf("asset must be ecosystem/package@version: %q", s)
	}
	ecosystem := strings.TrimSpace(ec)
	pkg := strings.TrimSpace(pk)
	if ecosystem == "" || pkg == "" || version == "" {
		return models.Asset{}, fmt.Errorf("asset ecosystem, package, and version are required: %q", s)
	}
	name := pkg
	if last := strings.LastIndex(pkg, "/"); last >= 0 {
		name = pkg[last+1:]
	}
	return models.Asset{
		Name:      name,
		Package:   pkg,
		Ecosystem: ecosystem,
		Version:   version,
	}, nil
}

// parsePURL accepts "pkg:type/name@version". Namespace and qualifiers are ignored
// for the simple OSV query use-case.
func parsePURL(s string) (models.Asset, error) {
	withoutPrefix := strings.TrimPrefix(s, "pkg:")
	at := strings.LastIndex(withoutPrefix, "@")
	if at < 0 {
		return models.Asset{}, fmt.Errorf("purl must contain @version: %q", s)
	}
	version := strings.TrimSpace(withoutPrefix[at+1:])
	left := strings.TrimSpace(withoutPrefix[:at])

	// Strip qualifiers and subpath.
	if before, _, ok := strings.Cut(left, "?"); ok {
		left = before
	}
	if before, _, ok := strings.Cut(left, "#"); ok {
		left = before
	}

	ec, namePart, ok := strings.Cut(left, "/")
	if !ok {
		return models.Asset{}, fmt.Errorf("purl must contain type/name: %q", s)
	}

	ecosystem := strings.TrimSpace(ec)
	namePart = strings.TrimSpace(namePart)
	if ecosystem == "" || namePart == "" || version == "" {
		return models.Asset{}, fmt.Errorf("purl type, name, and version are required: %q", s)
	}

	// If there is a namespace, take the final segment as the package name for OSV.
	pkg := namePart
	if last := strings.LastIndex(namePart, "/"); last >= 0 {
		pkg = namePart[last+1:]
	}

	return models.Asset{
		Name:      pkg,
		Package:   namePart,
		Ecosystem: ecosystem,
		Version:   version,
	}, nil
}

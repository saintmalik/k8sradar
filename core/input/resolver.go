package input

import (
	"github.com/abdulmalik/k8sradar/core/models"
)

// Flags carries CLI values plus a record of which flags were explicitly set.
type Flags struct {
	Provider   string
	K8sVersion string
	NodeOS     string
	Components []models.ComponentVersion
	Assets     []models.Asset
	Changed    map[string]bool
}

// Resolve merges a config file/ stdin StackConfig with explicit CLI flags.
// Precedence: file defaults < CLI overrides (only when Changed).
func Resolve(file StackConfig, flags Flags) models.ClusterInput {
	input := models.ClusterInput{
		Provider:   normalizeProvider(file.Provider),
		K8sVersion: file.K8sVersion,
		NodeOS:     file.NodeOS,
		Components: file.Components,
		Assets:     file.Assets,
	}

	if flags.Changed["provider"] {
		input.Provider = normalizeProvider(flags.Provider)
	}
	if flags.Changed["k8s-version"] {
		input.K8sVersion = flags.K8sVersion
	}
	if flags.Changed["node-os"] {
		input.NodeOS = flags.NodeOS
	}
	if flags.Changed["component"] {
		input.Components = mergeComponents(input.Components, flags.Components)
	}
	if flags.Changed["asset"] {
		input.Assets = append(input.Assets, flags.Assets...)
	}

	return input
}

func normalizeProvider(raw string) models.Provider {
	p := models.Provider(raw)
	if p == "" {
		return ""
	}
	return p
}

// mergeComponents appends CLI overrides to file components, with later values
// for the same component name winning.
func mergeComponents(base, overrides []models.ComponentVersion) []models.ComponentVersion {
	merged := make([]models.ComponentVersion, 0, len(base)+len(overrides))
	byName := map[string]int{}

	for _, c := range base {
		idx := len(merged)
		merged = append(merged, c)
		byName[c.Name] = idx
	}
	for _, c := range overrides {
		if idx, ok := byName[c.Name]; ok {
			merged[idx] = c
		} else {
			byName[c.Name] = len(merged)
			merged = append(merged, c)
		}
	}
	return merged
}

package cli

import (
	"fmt"
	"strings"

	"github.com/abdulmalik/k8sradar/core/input"
	"github.com/abdulmalik/k8sradar/core/models"
)

// componentFlagValue is a custom pflag.Value that parses "name=version".
type componentFlagValue struct {
	values *[]models.ComponentVersion
}

func newComponentFlagValue(p *[]models.ComponentVersion) *componentFlagValue {
	return &componentFlagValue{values: p}
}

func (c *componentFlagValue) String() string {
	if c.values == nil {
		return ""
	}
	parts := make([]string, 0, len(*c.values))
	for _, v := range *c.values {
		parts = append(parts, fmt.Sprintf("%s=%s", v.Name, v.Version))
	}
	return strings.Join(parts, ",")
}

func (c *componentFlagValue) Set(s string) error {
	comp, err := input.ParseComponentFlag(s)
	if err != nil {
		return err
	}
	*c.values = append(*c.values, comp)
	return nil
}

func (c *componentFlagValue) Type() string { return "name=version" }

// assetFlagValue is a custom pflag.Value that parses an asset reference.
type assetFlagValue struct {
	values *[]models.Asset
}

func newAssetFlagValue(p *[]models.Asset) *assetFlagValue {
	return &assetFlagValue{values: p}
}

func (a *assetFlagValue) String() string {
	if a.values == nil {
		return ""
	}
	parts := make([]string, 0, len(*a.values))
	for _, v := range *a.values {
		parts = append(parts, fmt.Sprintf("%s/%s@%s", v.Ecosystem, v.Package, v.Version))
	}
	return strings.Join(parts, ",")
}

func (a *assetFlagValue) Set(s string) error {
	asset, err := input.ParseAssetFlag(s)
	if err != nil {
		return err
	}
	*a.values = append(*a.values, asset)
	return nil
}

func (a *assetFlagValue) Type() string { return "ecosystem/package@version" }

// formatSplit splits a comma-separated output list and normalizes names.
func formatSplit(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(strings.ToLower(r))
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

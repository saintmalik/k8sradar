package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/abdulmalik/k8sradar/core/cache"
	"github.com/abdulmalik/k8sradar/core/cvss"
	"github.com/abdulmalik/k8sradar/core/models"
	"github.com/abdulmalik/k8sradar/core/providers"
	"github.com/abdulmalik/k8sradar/core/sources/epss"
	"github.com/abdulmalik/k8sradar/core/sources/nvd"
	"github.com/abdulmalik/k8sradar/core/sources/osv"
)

type Scanner struct {
	DB       *cache.DB
	OSV      *osv.Client
	EPSS     *epss.Client
	NVD      *nvd.Client
	Registry *providers.Registry
}

func (s *Scanner) Scan(ctx context.Context, input models.ClusterInput) ([]models.EnrichedCVE, error) {
	var components []models.ComponentVersion
	var catalog map[string]models.ComponentDefinition

	if input.Provider != "" {
		provider, err := s.Registry.Get(input.Provider)
		if err != nil {
			return nil, err
		}

		components = input.Components
		if len(components) == 0 {
			components, err = provider.DefaultComponents(ctx, input.K8sVersion, input.NodeOS)
			if err != nil {
				return nil, err
			}
		}

		catalog = map[string]models.ComponentDefinition{}
		for _, c := range provider.Catalog() {
			catalog[c.Name] = c
		}

		if input.K8sVersion != "" {
			found := false
			for _, c := range components {
				if c.Name == "kubernetes" && c.Version != "" {
					found = true
					break
				}
			}
			if !found {
				components = append([]models.ComponentVersion{{
					Name: "kubernetes", Version: strings.TrimPrefix(input.K8sVersion, "v"),
				}}, components...)
			}
		}
	}

	if len(input.Assets) == 0 && input.Provider == "" {
		return nil, fmt.Errorf("provider or at least one asset is required")
	}

	var queries []models.OSVQuery
	for _, comp := range components {
		if comp.Version == "" {
			continue
		}
		def, ok := catalog[comp.Name]
		if !ok {
			continue
		}
		queries = append(queries, models.OSVQuery{
			Package:   def.OSVPackage,
			Ecosystem: def.OSVEcosystem,
			Version:   normalizeVersion(comp.Version),
			Component: def.Label,
		})
	}

	for _, a := range input.Assets {
		if a.Version == "" {
			continue
		}
		name := a.Name
		if name == "" {
			name = a.Package
		}
		queries = append(queries, models.OSVQuery{
			Package:   a.Package,
			Ecosystem: a.Ecosystem,
			Version:   normalizeVersion(a.Version),
			Component: name,
			Asset:     name,
		})
	}

	findings, err := s.OSV.QueryBatch(ctx, s.DB, queries)
	if err != nil {
		return nil, err
	}

	var cveIDs []string
	seenCVE := map[string]struct{}{}
	for _, f := range findings {
		for _, id := range f.CVEIDs {
			if !strings.HasPrefix(id, "CVE-") {
				continue
			}
			if _, ok := seenCVE[id]; ok {
				continue
			}
			seenCVE[id] = struct{}{}
			cveIDs = append(cveIDs, id)
		}
	}
	if s.EPSS != nil {
		_ = s.EPSS.Lookup(ctx, s.DB, cveIDs)
	}
	if s.NVD != nil {
		nvdIDs := cveIDsNeedingNVD(ctx, s.DB, findings, cveIDs)
		if len(nvdIDs) > 0 {
			enrichCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			defer cancel()
			_ = s.NVD.EnrichCVEs(enrichCtx, s.DB, nvdIDs)
		}
	}

	byKey := map[string]models.EnrichedCVE{}
	for _, f := range findings {
		primaryID := f.OSVID
		if len(f.CVEIDs) > 0 {
			primaryID = f.CVEIDs[0]
		}

		enriched := models.EnrichedCVE{
			ID:               primaryID,
			Description:      f.Summary,
			CVSSScore:        f.CVSSScore,
			CVSSVector:       f.CVSSVector,
			Component:        f.Component,
			InstalledVersion: f.InstalledVersion,
			FixedIn:          f.FixedIn,
			Source:           "osv",
			Asset:            f.Asset,
		}

		if cve, _ := s.DB.GetCVE(ctx, primaryID); cve != nil {
			if cve.CVSSScore > 0 {
				enriched.CVSSScore = cve.CVSSScore
			}
			if cve.CVSSVector != "" {
				enriched.CVSSVector = cve.CVSSVector
			}
			if cve.Description != "" {
				enriched.Description = cve.Description
			}
			enriched.Source = "both"
		}

		if score, pct, ok, _ := s.DB.GetEPSS(ctx, primaryID); ok {
			enriched.EPSSScore = score
			enriched.EPSSPercentile = pct
		}

		if inKEV, _ := s.DB.InKEV(ctx, primaryID); inKEV {
			enriched.InKEV = true
		}

		enriched.RemoteExploitable = cvss.RemoteExploitable(enriched.CVSSVector)
		enriched.Severity = cvss.Severity(enriched.CVSSScore)

		key := primaryID + "|" + f.Component
		if existing, ok := byKey[key]; ok {
			if enriched.CVSSScore > existing.CVSSScore {
				byKey[key] = enriched
			}
			continue
		}
		byKey[key] = enriched
	}

	out := make([]models.EnrichedCVE, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, v)
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.InKEV != b.InKEV {
			return a.InKEV
		}
		sra, srb := cvss.SeverityRank(a.Severity), cvss.SeverityRank(b.Severity)
		if sra != srb {
			return sra > srb
		}
		if a.EPSSScore != b.EPSSScore {
			return a.EPSSScore > b.EPSSScore
		}
		return a.CVSSScore > b.CVSSScore
	})

	return out, nil
}

func cveIDsNeedingNVD(ctx context.Context, db *cache.DB, findings []osv.Finding, cveIDs []string) []string {
	osvScores := map[string]float64{}
	for _, f := range findings {
		if f.CVSSScore <= 0 {
			continue
		}
		for _, id := range f.CVEIDs {
			if !strings.HasPrefix(id, "CVE-") {
				continue
			}
			if f.CVSSScore > osvScores[id] {
				osvScores[id] = f.CVSSScore
			}
		}
	}

	var out []string
	for _, id := range cveIDs {
		if osvScores[id] > 0 {
			continue
		}
		if cve, _ := db.GetCVE(ctx, id); cve != nil && cve.CVSSScore > 0 {
			continue
		}
		out = append(out, id)
	}
	return out
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	// strip build metadata for semver packages like v1.11.1-eksbuild1
	if idx := strings.Index(v, "-"); idx > 0 {
		// keep EKS-style suffixes for OSV — try full first, OSV handles semver
	}
	return v
}

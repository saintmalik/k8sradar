package presenter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/abdulmalik/k8sradar/core/models"
)

// SARIF writes a SARIF 2.1.0 document with one result per CVE finding.
type SARIF struct{}

func (SARIF) Name() string        { return "sarif" }
func (SARIF) Extension() string   { return ".sarif" }
func (SARIF) ContentType() string { return "application/sarif+json" }

func (SARIF) Present(w io.Writer, report models.ScanReport) error {
	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			buildRun(report),
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func buildRun(report models.ScanReport) sarifRun {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "k8sradar",
				InformationURI: "https://github.com/abdulmalik/k8sradar",
				Rules:          []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	ruleIndex := map[string]int{}
	for _, r := range report.Results {
		if _, ok := ruleIndex[r.ID]; ok {
			continue
		}
		idx := len(run.Tool.Driver.Rules)
		ruleIndex[r.ID] = idx
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:   r.ID,
			Name: r.ID,
			ShortDescription: sarifText{
				Text: firstLine(r.Description),
			},
			FullDescription: sarifText{
				Text: r.Description,
			},
			DefaultConfiguration: sarifConfig{
				Level: severityToSARIFLevel(r.Severity),
			},
			HelpURI: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", r.ID),
			Properties: sarifRuleProps{
				Tags: []string{"security"},
			},
		})
	}

	// Sort results for deterministic output.
	sorted := make([]models.EnrichedCVE, len(report.Results))
	copy(sorted, report.Results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Component < sorted[j].Component
	})

	for _, r := range sorted {
		result := sarifResult{
			RuleID:  r.ID,
			RuleIndex: ruleIndex[r.ID],
			Level:   severityToSARIFLevel(r.Severity),
			Message: sarifText{
				Text: fmt.Sprintf("%s affects %s %s (installed: %s). EPSS %.4f. Fixed in %s.",
					r.ID, r.Component, r.Severity, r.InstalledVersion, r.EPSSScore, defaultEmpty(r.FixedIn, "unknown")),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: artifactURI(report.Input, r),
						},
						Region: sarifRegion{
							StartLine: 1,
							EndLine:   1,
						},
					},
				},
			},
			Properties: sarifResultProps{
				Component:         r.Component,
				InstalledVersion: r.InstalledVersion,
				FixedIn:           r.FixedIn,
				Severity:          r.Severity,
				CVSSScore:         r.CVSSScore,
				EPSSScore:         r.EPSSScore,
				EPSSPercentile:    r.EPSSPercentile,
				InKEV:             r.InKEV,
				RemoteExploitable: r.RemoteExploitable,
			},
		}
		run.Results = append(run.Results, result)
	}

	return run
}

func artifactURI(input models.ClusterInput, result models.EnrichedCVE) string {
	if input.Provider != "" {
		return fmt.Sprintf("pkg:kubernetes/%s/%s@%s", input.Provider, result.Component, result.InstalledVersion)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", result.Component, result.InstalledVersion)
}

func severityToSARIFLevel(sev string) string {
	switch sev {
	case "Critical":
		return "error"
	case "High":
		return "error"
	case "Medium":
		return "warning"
	case "Low":
		return "note"
	default:
		return "note"
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func defaultEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

type sarifDocument struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	HelpURI              string         `json:"helpUri"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Properties sarifResultProps `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifResultProps struct {
	Component         string  `json:"component"`
	InstalledVersion  string  `json:"installedVersion"`
	FixedIn           string  `json:"fixedIn"`
	Severity          string  `json:"severity"`
	CVSSScore         float64 `json:"cvssScore"`
	EPSSScore         float64 `json:"epssScore"`
	EPSSPercentile    float64 `json:"epssPercentile"`
	InKEV             bool    `json:"inKEV"`
	RemoteExploitable bool    `json:"remoteExploitable"`
}

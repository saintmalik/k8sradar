package slack

import (
	"fmt"
	"strings"
)

type slackBlock struct {
	Type string      `json:"type"`
	Text *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

func headerBlock(text string) slackBlock {
	return slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: text, Emoji: true},
	}
}

func sectionBlock(text string, fields ...slackText) slackBlock {
	b := slackBlock{Type: "section", Text: &slackText{Type: "mrkdwn", Text: text}}
	if len(fields) > 0 {
		b.Fields = fields
	}
	return b
}

func dividerBlock() slackBlock {
	return slackBlock{Type: "divider"}
}

func markdown(text string) slackText {
	return slackText{Type: "mrkdwn", Text: text}
}

func buildBlocks(summary Summary, files []string, canUpload bool) []slackBlock {
	blocks := []slackBlock{
		headerBlock(summary.Title),
		sectionBlock(fmt.Sprintf("*Scanned at:* %s", summary.ScannedAt)),
	}

	if summary.Provider != "" {
		blocks = append(blocks, sectionBlock(fmt.Sprintf("*Provider:* %s", summary.Provider)))
	}
	if summary.K8sVersion != "" {
		blocks = append(blocks, sectionBlock(fmt.Sprintf("*K8s version:* %s", summary.K8sVersion)))
	}

	blocks = append(blocks, dividerBlock())
	blocks = append(blocks, sectionBlock("", markdown(fmt.Sprintf("*Total CVEs:*\n%d", summary.TotalCVEs))))

	severityOrder := []string{"Critical", "High", "Medium", "Low", "Unknown"}
	fields := []slackText{markdown(fmt.Sprintf("*KEV:*\n%d", summary.KEVCount))}
	for _, sev := range severityOrder {
		count := summary.SeverityCounts[sev]
		fields = append(fields, markdown(fmt.Sprintf("*%s:*\n%d", sev, count)))
	}
	if summary.MaxEPSS > 0 {
		fields = append(fields, markdown(fmt.Sprintf("*Max EPSS:*\n%.4f", summary.MaxEPSS)))
	}
	blocks = append(blocks, sectionBlock("", fields...))

	if summary.Gate != "" {
		status := "✅ passed"
		if summary.GateBreached {
			status = "❌ breached"
		}
		blocks = append(blocks, sectionBlock(fmt.Sprintf("*Gate (--fail-on %s):* %s", summary.Gate, status)))
	}

	if len(summary.TopFindings) > 0 {
		blocks = append(blocks, dividerBlock())
		b := &strings.Builder{}
		fmt.Fprintln(b, "*Top findings:*")
		for _, f := range summary.TopFindings {
			kev := ""
			if f.InKEV {
				kev = " ⭐ KEV"
			}
			fmt.Fprintf(b, "• <%s|%s> — %s / %s | EPSS %.4f%s\n",
				cveURL(f.ID), f.ID, f.Severity, f.Component, f.EPSS, kev)
		}
		blocks = append(blocks, sectionBlock(strings.TrimRight(b.String(), "\n")))
	}

	if len(files) > 0 {
		blocks = append(blocks, dividerBlock())
		if canUpload {
			blocks = append(blocks, sectionBlock(fmt.Sprintf("*Report files:* %s", strings.Join(files, ", "))))
		} else {
			blocks = append(blocks, sectionBlock(fmt.Sprintf("⚠️ Report files were generated but cannot be uploaded via webhook: %s", strings.Join(files, ", "))))
		}
	}

	return blocks
}


func cveURL(id string) string {
	if len(id) >= 4 && id[:4] == "CVE-" {
		return "https://nvd.nist.gov/vuln/detail/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

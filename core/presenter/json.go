package presenter

import (
	"encoding/json"
	"io"

	"github.com/abdulmalik/k8sradar/core/models"
)

// JSON writes the scan report as indented JSON.
type JSON struct{}

func (JSON) Name() string        { return "json" }
func (JSON) Extension() string   { return ".json" }
func (JSON) ContentType() string { return "application/json" }

func (JSON) Present(w io.Writer, report models.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

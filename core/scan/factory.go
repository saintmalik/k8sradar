package scan

import (
	"github.com/abdulmalik/k8sradar/core/cache"
	"github.com/abdulmalik/k8sradar/core/config"
	"github.com/abdulmalik/k8sradar/core/providers"
	"github.com/abdulmalik/k8sradar/core/sources/epss"
	"github.com/abdulmalik/k8sradar/core/sources/nvd"
	"github.com/abdulmalik/k8sradar/core/sources/osv"
)

// New builds a Scanner from application configuration and an open cache.
func New(cfg config.Config, db *cache.DB, reg *providers.Registry) *Scanner {
	return &Scanner{
		DB:       db,
		OSV:      osv.New(),
		EPSS:     epss.New(),
		NVD:      nvd.New(cfg.NVDAPIKey),
		Registry: reg,
	}
}

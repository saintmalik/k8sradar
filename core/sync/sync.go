package sync

import (
	"context"
	"fmt"
	"log"

	"github.com/abdulmalik/k8sradar/core/cache"
	"github.com/abdulmalik/k8sradar/core/sources/epss"
	"github.com/abdulmalik/k8sradar/core/sources/kev"
	"github.com/abdulmalik/k8sradar/core/sources/nvd"
)

type Runner struct {
	DB        *cache.DB
	NVDAPIKey string
}

func (r *Runner) RunAll(ctx context.Context) error {
	log.Println("sync: KEV...")
	n, err := kev.New().Sync(ctx, r.DB)
	if err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	log.Printf("sync: KEV done (%d entries)", n)

	log.Println("sync: EPSS (this may take a minute)...")
	n, err = epss.New().Sync(ctx, r.DB)
	if err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	log.Printf("sync: EPSS done (%d entries)", n)

	log.Println("sync: NVD keywords (limited pages)...")
	n, err = nvd.New(r.NVDAPIKey).SyncKeywords(ctx, r.DB, 2)
	if err != nil {
		return fmt.Errorf("nvd: %w", err)
	}
	log.Printf("sync: NVD done (%d CVEs)", n)

	return nil
}

func (r *Runner) RunKEV(ctx context.Context) (int, error) {
	return kev.New().Sync(ctx, r.DB)
}

func (r *Runner) RunEPSS(ctx context.Context) (int, error) {
	return epss.New().Sync(ctx, r.DB)
}

func (r *Runner) RunNVD(ctx context.Context, maxPages int) (int, error) {
	return nvd.New(r.NVDAPIKey).SyncKeywords(ctx, r.DB, maxPages)
}

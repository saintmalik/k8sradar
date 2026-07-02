package main

import (
	"os"

	"github.com/saintmalik/k8sradar/cli/internal/cli"
)

func main() {
	if err := cli.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

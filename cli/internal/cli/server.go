package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var (
		file string
		dir  string
		port string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve generated HTML reports locally",
		Long: `Starts a lightweight static file server for viewing k8sradar HTML reports.
This is not the deployed web app; it only serves files you have already generated.`,
		Example: `  k8sradar serve --file ./reports/k8sradar-report.html
  k8sradar serve --dir ./reports --port 8080`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(file, dir, port)
		},
	}

	cmd.Flags().StringVar(&file, "file", "", "Specific HTML report to serve")
	cmd.Flags().StringVar(&dir, "dir", ".", "Directory containing HTML reports")
	cmd.Flags().StringVar(&port, "port", "8080", "HTTP port")
	return cmd
}

func runServe(file, dir, port string) error {
	if file != "" {
		abs, err := filepath.Abs(file)
		if err != nil {
			return fmt.Errorf("resolve file: %w", err)
		}
		dir = filepath.Dir(abs)
		base := filepath.Base(abs)
		log.Printf("serving report at http://localhost:%s/%s", port, base)
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, abs)
		})
		return listenAndServe(mux, port)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve directory: %w", err)
	}
	log.Printf("serving reports from %s at http://localhost:%s", abs, port)
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(abs)))
	return listenAndServe(mux, port)
}

func listenAndServe(handler http.Handler, port string) error {
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	return srv.ListenAndServe()
}

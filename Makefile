.PHONY: all build cli server test tidy docker example-config

all: cli server

build: cli

cli:
	cd cli && go build -o ../bin/k8sradar ./cmd/k8sradar

server:
	cd server && go run github.com/a-h/templ/cmd/templ@v0.3.1020 generate ./web/... && go build -o ../bin/k8sradar-server ./cmd/server

run-server: server
	./bin/k8sradar-server

run-cli: cli
	./bin/k8sradar --help

sync:
	cd server && go run ./cmd/server --sync

seed:
	cd server && go run ./cmd/seeddb

test:
	cd core && go test ./...
	cd cli && go test ./...
	cd server && go test ./...

tidy:
	cd core && go mod tidy
	cd cli && go mod tidy
	cd server && go mod tidy

docker:
	cd server && docker build -t k8sradar-server .

example-config:
	@echo 'provider: eks'
	@echo 'k8s_version: "1.31"'
	@echo 'node_os: al2023'
	@echo 'components:'
	@echo '  - name: kubernetes'
	@echo '    version: "1.31.2"'

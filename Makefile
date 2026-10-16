VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all web build test release docker clean dev

all: web build

web:
	cd web && npm ci && npm run build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o waf ./cmd/waf

test:
	go vet ./...
	go test ./...
	cd web && npm run typecheck

# 交叉编译 Linux 二进制（amd64 + arm64），上传到服务器即可运行
release: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/waf-linux-amd64 ./cmd/waf
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/waf-linux-arm64 ./cmd/waf

docker:
	docker build -t waf:$(VERSION) .

# 本地开发：先 `go run ./cmd/waf serve -c dev.yaml`（admin.tls: off, listen 127.0.0.1:9443），再运行此目标
dev:
	cd web && npm run dev

clean:
	rm -rf waf dist web/node_modules
	find web/dist -mindepth 1 ! -name .gitkeep -delete

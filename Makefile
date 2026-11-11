.PHONY: all web build nocf release clean test

all: build

web:
	cd web && npm ci && npm run build

# Host build with cloudflared embedded -> ./oncedrop
build: web
	go run ./tools/release

# Small build without cloudflared (uses one from PATH, or localhost.run).
nocf: web
	go run ./tools/release -no-cloudflared

# Every platform -> dist/
release: web
	go run ./tools/release -all

clean:
	rm -rf oncedrop oncedrop.exe dist

test:
	go test -race ./...

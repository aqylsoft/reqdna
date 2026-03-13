.PHONY: all test bench lint build clean release

# Default target
all: lint test build

# Run tests
test:
	go test -race -cover ./...

# Run tests with verbose output
test-v:
	go test -race -cover -v ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run linters
lint:
	go vet ./...
	@which staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

# Build
build:
	go build ./...

# Clean
clean:
	go clean ./...

# Create a new release (usage: make release VERSION=v0.2.0)
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=v0.2.0)
endif
	@echo "Creating release $(VERSION)..."
	@git diff --quiet || (echo "Error: working directory not clean" && exit 1)
	@git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Tag $(VERSION) created. Push with: git push origin $(VERSION)"

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Run lint, test, build (default)"
	@echo "  test     - Run tests with race detection"
	@echo "  test-v   - Run tests with verbose output"
	@echo "  bench    - Run benchmarks"
	@echo "  lint     - Run go vet and staticcheck"
	@echo "  build    - Build all packages"
	@echo "  clean    - Clean build artifacts"
	@echo "  release  - Create a git tag (VERSION=v0.x.x required)"

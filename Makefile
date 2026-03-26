.PHONY: test vet lint clean

GO ?= go

# Run all tests with verbose output
test:
	$(GO) test ./... -v -count=1

# Run tests with race detector
test-race:
	$(GO) test ./... -v -race -count=1

# Run go vet on all packages
vet:
	$(GO) vet ./...

# Run staticcheck if available, otherwise just vet
lint: vet
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping (install: go install honnef.co/go/tools/cmd/staticcheck@latest)"

# Build check (library only, no binary)
build:
	$(GO) build ./...

# Run all checks
check: vet lint test

# Clean test cache
clean:
	$(GO) clean -testcache

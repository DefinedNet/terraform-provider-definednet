BINARY  := terraform-provider-definednet
VERSION ?= dev

.PHONY: build install test testv docs fmt vet lint ready

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

# Installs into GOPATH/bin for use with a dev_overrides block; see README.md.
install:
	go install -ldflags "-X main.version=$(VERSION)" .

test:
	go test $(TEST_FLAGS) ./...

testv: TEST_FLAGS += -v
testv: test

docs:
	go tool tfplugindocs generate --provider-name definednet

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run ./...

ready: fmt vet lint test docs

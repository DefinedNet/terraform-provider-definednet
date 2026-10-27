BINARY  := terraform-provider-definednet
VERSION ?= dev

.PHONY: build install test testv testacc sweep docs fmt vet lint ready

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

# Installs into GOPATH/bin for use with a dev_overrides block; see README.md.
install:
	go install -ldflags "-X main.version=$(VERSION)" .

test:
	go test ./...

testv:
	go test -v ./...

# Runs against the real API; see README.md for the environment it needs.
testacc:
	TF_ACC=1 go test ./internal/provider -run '^TestAcc' -v -count=1 -timeout 60m

# Deletes objects a crashed acceptance run left behind.
sweep:
	go test ./internal/provider -v -sweep=all -timeout 10m

docs:
	go tool tfplugindocs generate --provider-name definednet

fmt:
	gofmt -w .

vet:
	go vet ./...

ready: fmt vet test docs

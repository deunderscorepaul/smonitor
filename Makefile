# Go parameters
BINARY_NAME=smonitor
MAIN_PATH=./cmd/smonitor
VERSION=1.0.0
BUILD_FLAGS=-trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux-amd64 build-linux-arm64 build-linux-armv7 clean test

all: build-linux-arm64

## build: Build binary for host OS
build:
	go build $(BUILD_FLAGS) -o bin/$(BINARY_NAME) $(MAIN_PATH)

## build-linux-amd64: Build pure-Go single static binary for Linux x86_64
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)

## build-linux-arm64: Build pure-Go single static binary for Linux ARM64 (Raspberry Pi 4/5 / Pi OS 64-bit)
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o bin/$(BINARY_NAME)-linux-arm64 $(MAIN_PATH)

## build-linux-armv7: Build pure-Go single static binary for Linux 32-bit ARM (Raspberry Pi 2/3 / Pi OS 32-bit)
build-linux-armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(BUILD_FLAGS) -o bin/$(BINARY_NAME)-linux-armv7 $(MAIN_PATH)

## test: Run unit tests
test:
	go test -v ./...

## clean: Remove build artifacts
clean:
	rm -rf bin/

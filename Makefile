VERSION=$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)
GOFLAGS=-ldflags "-w -s -X main.version=$(VERSION)"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

GEN=block/block.pb.go node/node.pb.go

blk: $(GEN)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) ./cmd/blk

all: blk blk-arm blk-darwin

install: $(GEN)
	go install $(GOFLAGS) ./cmd/blk

gen: $(GEN)

%.pb.go:
	go generate ./...

blk-arm: $(GEN)
	GOARCH=arm GOARM=6 go build $(GOFLAGS) -o $@ ./cmd/blk

blk-darwin: $(GEN)
	GOOS=darwin go build $(GOFLAGS) -o $@ ./cmd/blk

clean:
	$(RM) ./blk ./blkmine blk-arm blk-darwin
	go clean -i ./cmd/blk

cleanpb:
	$(RM) $(shell find . -name '*.pb.go')

.PHONY: install build gen clean cleanpb


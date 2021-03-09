GOFILES=$(shell find . -name '*.go' -type f | sort)
VERSION=$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)
COMMIT=$(shell git rev-parse HEAD)
#HASH=$(shell sha256sum <(find . -name '*.go' -type f | sort))
HASH=$(shell cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/\s|-//g')

DATE=$(shell date -R)
GOFLAGS=-ldflags "-w -s \
		-X 'github.com/harrybrwn/go-ledger/cli.version=$(VERSION)' \
		-X 'github.com/harrybrwn/go-ledger/cli.built=$(DATE)' \
		-X 'github.com/harrybrwn/go-ledger/cli.commit=$(COMMIT)' \
		-X 'github.com/harrybrwn/go-ledger/cli.hash=$(HASH)'"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

#BINDIR=/usr/local/bin
BINDIR=$$HOME/dev/go/bin

GEN=block/block.pb.go node/node.pb.go

blk: $(GEN)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) ./cmd/blk

all: blk blk-arm blk-darwin

install: blk
	@install ./blk $(BINDIR)
	@rm ./blk

uninstall: $(GEN)
	sudo rm $(BINDIR)/blk

systemd:
	systemctl --user disable --now blk-ledger
	cp systemd/blk-ledger.service ~/.config/systemd/user
	systemctl --user enable --now blk-ledger

gen: $(GEN)

%.pb.go:
	go generate ./...

blk-arm: $(GEN)
	GOARCH=arm GOARM=6 go build $(GOFLAGS) -o $@ ./cmd/blk

blk-darwin: $(GEN)
	GOOS=darwin go build $(GOFLAGS) -o $@ ./cmd/blk

clean:
	$(RM) -r build dist ./blk ./blkmine blk-arm blk-darwin
	go clean -i ./cmd/blk

cleanpb:
	$(RM) $(shell find . -name '*.pb.go')

systemd-logs:
	journalctl --user -afu blk-ledger

.PHONY: install build gen clean cleanpb systemd

hash:
	@cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/[\s-]+//g'


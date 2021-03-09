GOFILES=$(shell find . -name '*.go' -type f | sort)
VERSION=$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)
COMMIT=$(shell git rev-parse HEAD)
#HASH=$(shell sha256sum <(find . -name '*.go' -type f | sort))
HASH=$(shell cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/\s|-//g')

DATE=$(shell date -R)
GOFLAGS=-ldflags "-w -s \
		-X 'github.com/harrybrwn/go-vine/cli.version=$(VERSION)' \
		-X 'github.com/harrybrwn/go-vine/cli.built=$(DATE)' \
		-X 'github.com/harrybrwn/go-vine/cli.commit=$(COMMIT)' \
		-X 'github.com/harrybrwn/go-vine/cli.hash=$(HASH)'"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

#BINDIR=/usr/local/bin
BINDIR=$$HOME/dev/go/bin

GEN=block/block.pb.go node/node.pb.go

vine: $(GEN)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) ./cmd/vine

install: vine
	@install ./vine $(BINDIR)
	@rm ./vine

uninstall: $(GEN)
	sudo rm $(BINDIR)/vine

systemd:
	systemctl --user disable --now blk-ledger
	cp systemd/blk-ledger.service ~/.config/systemd/user
	systemctl --user enable --now blk-ledger

gen: $(GEN)

%.pb.go:
	go generate ./...

clean:
	$(RM) -r build dist ./vine ./blk ./blkmine blk-arm blk-darwin
	go clean -i ./cmd/vine

cleanpb:
	$(RM) $(shell find . -name '*.pb.go')

systemd-logs:
	journalctl --user -afu blk-ledger

.PHONY: install build gen clean cleanpb systemd

hash:
	@cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/[\s-]+//g'


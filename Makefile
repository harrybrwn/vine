GOFILES=$(shell find . -name '*.go' -type f | sort)
VERSION=$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)
COMMIT=$(shell git rev-parse HEAD)
HASH=$(shell cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/\s|-//g')

DATE=$(shell date -R)
GOFLAGS=-trimpath       \
		-buildmode=exe  \
		-ldflags "-w -s \
			-X 'github.com/harrybrwn/vine/cli.version=$(VERSION)' \
			-X 'github.com/harrybrwn/vine/cli.date=$(DATE)'       \
			-X 'github.com/harrybrwn/vine/cli.commit=$(COMMIT)'   \
			-X 'github.com/harrybrwn/vine/cli.hash=$(HASH)'"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

#BINDIR=/usr/local/bin
BINDIR=$$GOPATH/bin

GEN=block/block.pb.go node/node.pb.go
#t:
#	file ./vine-$(VERSION).deb

vine: $(GEN)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) ./cmd/vine

./bin/vine: $(GEN)
	@#mkdir ./bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $@ ./cmd/vine

install: vine
	@install ./vine $(BINDIR)
	@rm ./vine

uninstall: $(GEN)
	sudo rm $(BINDIR)/vine

systemd:
	systemctl --user disable --now vine
	cp systemd/vine.service ~/.config/systemd/user
	systemctl --user enable --now vine

gen: $(GEN)
	go generate ./block ./node

node/%.pb.go:
	go generate ./node

block/%.pb.go:
	go generate ./block

clean:
	$(RM) -r ./build ./bin ./dist ./vine ./vine.exe vine-$(VERSION).deb
	go clean -i ./cmd/vine

cleanpb:
	$(RM) $(shell find . -name '*.pb.go')

systemd-logs:
	journalctl --user -afu blk-ledger

.PHONY: install build gen clean cleanpb systemd

hash:
	@cat $(GOFILES) go.mod go.sum | sha256sum | sed -Ee 's/[\s-]+//g'

deb: vine-$(VERSION).deb
vine-$(VERSION).deb: scripts/deb.sh
	sh scripts/deb.sh vine-$(VERSION)

install-deb: vine-$(VERSION).deb
	sudo apt install -f ./$<

.PHONY: install-deb deb
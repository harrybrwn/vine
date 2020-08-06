install: block/block.pb.go node/node.pb.go
	go install ./cmd/blk

%.pb.go: %.proto
	go generate ./...

clean:
	$(RM) ./blk ./blkmine blk-arm blk-darwin $(shell find . -name '*.pb.go')
	go clean -i ./cmd/blk

build:
	go generate ./...
	go build ./cmd/blk

build-arm:
	GOARCH=arm GOARM=6 go build -o blk-arm ./cmd/blk

build-darwin:
	GOOS=darwin go build -o blk-darwin ./cmd/blk

.PHONY: clean

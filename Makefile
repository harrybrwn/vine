block/block.pb.go: block/block.proto
	protoc --go_out=./block $<

install:
	go install ./cmd/blk

clean:
	$(RM) ./blk ./blkmine blk-arm blk-darwin
	go clean -i ./cmd/blk

build:
	go generate ./...
	go build ./cmd/blk

build-arm:
	GOARCH=arm GOARM=6 go build -o blk-arm ./cmd/blk

build-darwin:
	GOOS=darwin go build -o blk-darwin ./cmd/blk

.PHONY: clean

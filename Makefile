block/block.pb.go: block/block.proto
	protoc --go_out=./block $<

install:
	go install ./cmd/blk

clean:
	@#find . -name '*.pb.go' -type f -exec rm "{}" \;
	$(RM) ./blk ./blkmine
	go clean -i ./cmd/blk

build:
	go generate ./...
	go build ./cmd/blk

.PHONY: clean

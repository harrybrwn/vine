block/block.pb.go: block/block.proto
	protoc --go_out=./block $<

clean:
	@#find . -name '*.pb.go' -type f -exec rm "{}" \;
	$(RM) ./blk ./blkmine

build:
	go generate ./...
	go build ./cmd/blk
	go build ./cmd/blkmine

.PHONY: clean

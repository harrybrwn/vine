block/block.pb.go: block/block.proto
	protoc --go_out=./block $<

clean:
	find . -name '*.pb.go' -type f -exec rm "{}" \;

.PHONY: clean

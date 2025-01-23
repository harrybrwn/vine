FROM golang:1.16-alpine as builder

RUN apk update && \
	apk upgrade && \
	apk add    \
		make   \
		git    \
		protoc \
		ca-certificates && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
	mkdir /usr/local/vine

RUN mkdir -p /usr/local/src/vine
COPY go.mod /usr/local/src/vine
COPY go.sum /usr/local/src/vine
WORKDIR /usr/local/src/vine

RUN go mod download && \
	go mod verify

COPY . /usr/local/src/vine
RUN go generate ./...
RUN make install BINDIR=/usr/local/bin

FROM alpine:3.14
COPY --from=builder /usr/local/bin/vine /usr/local/bin/vine
WORKDIR /


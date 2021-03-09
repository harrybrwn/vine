module github.com/harrybrwn/go-vine

go 1.16

require (
	github.com/dgraph-io/badger/v2 v2.0.3
	github.com/fatih/color v1.9.0
	github.com/golang/protobuf v1.4.2
	github.com/harrybrwn/config v0.1.2
	github.com/harrybrwn/errs v0.0.1
	github.com/harrybrwn/mdns v1.0.4-0.20200730094346-cab0f176f7ac
	github.com/jackpal/gateway v1.0.7
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/libp2p/go-libp2p v0.13.0
	github.com/libp2p/go-libp2p-core v0.8.5
	github.com/libp2p/go-libp2p-pubsub v0.4.1 // indirect
	github.com/mattn/go-runewidth v0.0.10 // indirect
	github.com/miekg/dns v1.1.31
	github.com/mr-tron/base58 v1.2.0
	github.com/multiformats/go-multiaddr v0.3.1
	github.com/multiformats/go-multiaddr-net v0.2.0
	github.com/nsf/termbox-go v0.0.0-20200418040025-38ba6e5628f1
	github.com/pkg/errors v0.9.1
	github.com/sevlyar/go-daemon v0.1.5
	github.com/sirupsen/logrus v1.6.1-0.20200528085638-6699a89a232f
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	google.golang.org/grpc v1.31.1
	google.golang.org/protobuf v1.23.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/harrybrwn/config => ../../pkg/config
	github.com/harrybrwn/mdns => ../../pkg/mdns
)

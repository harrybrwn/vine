package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/go-vine/blockstore"
	"github.com/harrybrwn/go-vine/key/wallet"
	"github.com/harrybrwn/go-vine/node"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/sevlyar/go-daemon"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func newDaemonCmd(flags *GlobalFlags) *cobra.Command {
	var (
		init    bool
		detatch bool
		kill    bool
	)
	c := &cobra.Command{
		Use:           "daemon",
		Short:         "Start the daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if init {
				err := initConfigDir(config.GetString("config"), blocksDir())
				if err != nil {
					return err
				}
			}
			pidFile := filepath.Join(config.GetString("config"), "daemon.pid")
			if kill {
				pid, err := daemon.ReadPidFile(pidFile)
				if err != nil {
					return err
				}
				p := &os.Process{Pid: pid}
				return p.Signal(os.Interrupt)
			}
			if detatch {
				ctx := &daemon.Context{
					PidFileName: pidFile,
					PidFilePerm: 0644,
					WorkDir:     config.GetString("config"),
					Umask:       027,
				}
				child, err := ctx.Reborn()
				if err != nil {
					return err
				}
				// exit the parent
				if child != nil {
					return nil
				}

				defer ctx.Release()
				defer log.Info("Stopping background daemon.")
				log.SetLevel(log.TraceLevel) // collect all logs
				log.WithFields(log.Fields{
					"pid":      os.Getpid(),
					"pid_file": pidFile,
				}).Info("Starting background daemon")
			}
			hooks := []daemonHook{
				events,
			}
			if flags.Silent {
				hooks = append(hooks, cliHook)
			}
			return runDaemon(hooks...)
		},
	}
	c.Flags().BoolVar(&init, "init", init, "initialize with default settings")
	c.Flags().BoolVarP(&detatch, "detach", "d", detatch, "detatch the daemon")
	c.Flags().BoolVarP(&kill, "kill", "k", kill, "kill a detatched daemon if one exists")
	return c
}

type daemonHook func(context.Context, host.Host, func())

func cliHook(ctx context.Context, host host.Host, cancel func()) {
	peers := host.Peerstore()
	sc := bufio.NewScanner(os.Stdin)
	info := func(id peer.ID) {
		fmt.Println("peer:", id, host.Network().Connectedness(id))
		fmt.Println("  info: ", host.Peerstore().PeerInfo(id))
		fmt.Println("  conns: [")
		for _, conn := range host.Network().ConnsToPeer(id) {
			fmt.Printf("    %[1]v\n", conn)
		}
		fmt.Println("  ]")
		fmt.Println("  tag:  ", host.ConnManager().GetTagInfo(id))
		fmt.Println()
	}

	fmt.Print("> ")
	for sc.Scan() {
		args := strings.Split(sc.Text(), " ")
		if len(args) < 1 {
			continue
		}
		command := args[0]
		args = args[1:]
		switch command {
		case "exit", "quit", ":q":
			cancel()
			return
		case "peers":
			for _, id := range peers.PeersWithAddrs() {
				info(id)
			}
		case "peer":
			info(peer.ID(args[0]))
		case "proto", "protos":
			for _, p := range host.Mux().Protocols() {
				fmt.Println(p)
			}
			fmt.Println()
		case "h", "help":
			fmt.Println(`daemon cli
	peers      -> list peers
	peer <id>  -> info for one peer
	protos     -> list host protocols
	exit|quit  -> end the program`)
		default:
		}
		fmt.Print("> ")
	}
}

func events(ctx context.Context, host host.Host, cancel func()) {
	bus := host.EventBus()
	peerids, err := bus.Subscribe(&event.EvtPeerIdentificationCompleted{})
	if err != nil {
		log.WithError(err).Error("could not subscribe to peer identification events")
		return
	}
	pidFail, err := bus.Subscribe(&event.EvtPeerIdentificationFailed{})
	if err != nil {
		log.WithError(err).Error("could not subscribe to peer identification failure events")
		return
	}
	addrup, err := bus.Subscribe(&event.EvtLocalAddressesUpdated{})
	if err != nil {
		log.WithError(err).Error("could not subscribe to address update events")
		return
	}
	conn, err := bus.Subscribe(&event.EvtPeerConnectednessChanged{})
	if err != nil {
		log.WithError(err).Error("could not subscribe to peer connectedness events")
		return
	}

	defer peerids.Close()
	defer pidFail.Close()
	defer addrup.Close()
	defer conn.Close()

	for {
		select {
		case out := <-conn.Out():
			e := out.(event.EvtPeerConnectednessChanged)
			var msg string
			switch e.Connectedness {
			case network.Connected:
				msg = "peer connected"
			case network.NotConnected:
				msg = "peer disconnected"
			default:
				msg = "peer connection state change"
			}
			log.WithFields(logrus.Fields{
				"peer":  e.Peer,
				"state": e.Connectedness,
			}).Info(msg)
		case out := <-pidFail.Out():
			e := out.(event.EvtPeerIdentificationFailed)
			log.WithFields(log.Fields{
				"addrs": host.Peerstore().Addrs(e.Peer),
				"id":    e.Peer,
			}).Info("identification failed")
		case out := <-peerids.Out():
			id := out.(event.EvtPeerIdentificationCompleted).Peer
			log.WithFields(log.Fields{
				"addrs": host.Peerstore().Addrs(id),
				"id":    id,
			}).Info("peer identified")
		case out := <-addrup.Out():
			log.WithFields(log.Fields{
				"event": fmt.Sprintf("%+v", out),
				"type":  fmt.Sprintf("%T", out),
			}).Info("local addresses updated")
		case <-ctx.Done():
			log.Trace("closing event handler")
			return
		}
	}
}

func runDaemon(hooks ...daemonHook) error {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var (
		walletname = config.GetString("wallet")
		w          *wallet.Wallet
		err        error
	)
	w, err = openWallet(walletname)
	if err != nil {
		return err
	}

	host, err := libp2p.New(ctx,
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.Identity(w),
	)
	if err != nil {
		return err
	}
	defer host.Close()

	// for testing
	host.SetStreamHandler("/msg", func(s network.Stream) {
		buf := new(bytes.Buffer)
		io.Copy(buf, s)
		log.Info(buf.String())
	})

	pid := os.Getpid()
	log.WithFields(log.Fields{
		"pid": pid, "node": host.ID().Pretty(),
	}).Infof("Starting full node")

	store, err := blockstore.Open(blocksDir())
	if err != nil {
		return err
	}
	fullnode, err := node.FullNode(ctx, host, store)
	if err != nil {
		return err
	}

	defer func() {
		if err = fullnode.Close(); err != nil {
			log.WithError(err).Warning("failed to close node")
		}
		if err = store.Close(); err != nil {
			log.WithError(err).Error("could not close block store")
		} else {
			time.Sleep(time.Second / 2) // hey man, this makes it look cool ok, don't judge
			log.Info("Graceful shutdown successful.")
		}
	}()

	srv := grpc.NewServer()
	node.RegisterBlockStoreServer(srv, fullnode)
	err = fullnode.StartWithGRPC(srv, node.GRPCProto)
	if err == context.Canceled {
		return nil
	} else if err != nil {
		return err
	}

	for _, h := range hooks {
		go h(ctx, host, stop)
	}

	var (
		termSigs  = make(chan os.Signal)
		killSigs  = make(chan os.Signal)
		intSigs   = make(chan os.Signal)
		reloadSig = make(chan os.Signal)
	)
	signal.Notify(termSigs, syscall.SIGTERM)
	signal.Notify(killSigs, os.Kill)
	signal.Notify(intSigs, os.Interrupt)
	signal.Notify(reloadSig, syscall.SIGHUP)
	defer func() {
		close(termSigs)
		close(killSigs)
		close(intSigs)
		close(reloadSig)
	}()

	go func() {
		for sig := range reloadSig {
			log.Info("reloading config: ", sig)
			err := config.ReadConfig()
			if err != nil {
				log.Error("config reload", err)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-termSigs:
		fmt.Print("\r") // hide the '^C'
		log.Info("Daemon was terminated")
		return &StatusError{Msg: "terminated", Code: 1}
	case <-killSigs:
		log.Info("Daemon was killed")
		return &StatusError{Msg: "killed", Code: 1}
	case <-intSigs:
		fmt.Print("\r") // hide the '^C'
		log.Info("Interupt received, shutting down...")
		return nil
	}
}

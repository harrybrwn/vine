package p2p

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"time"

	"github.com/harrybrwn/mdns"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"github.com/sirupsen/logrus"
)

var log = logrus.StandardLogger()

// DisableLogging will disable logging
func DisableLogging() {
	log.SetLevel(logrus.FatalLevel)
	log.SetOutput(ioutil.Discard)
	log.Hooks = nil
}

// Logger returns the logger
func Logger() *logrus.Logger {
	return log
}

// StartDiscovery will start a mdns discovery service that
// will send new peers down the channel
func StartDiscovery(
	ctx context.Context,
	self host.Host,
	service string,
	every time.Duration,
) (<-chan peer.AddrInfo, error) {
	ch := make(chan peer.AddrInfo)
	ticker := time.NewTicker(every)
	entries := make(chan *mdns.ServiceEntry, 32)
	srv, err := newMDNSServer(self, service)
	if err != nil {
		return ch, err
	}

	// handles the mDNS queries and shutdown
	go func() {
		for e := range entries {
			log.WithFields(logrus.Fields{
				"host": e.Host, "info": e.Info,
				"ipv4": e.AddrV4, "ipv6": e.AddrV6, "port": e.Port,
			}).Traceln("discovered:", e.Name)
			peerAddr, err := mDNSEntryToAddr(e)
			if err != nil {
				log.Debugf("mDNS entry to peer address failed: %v", err)
				continue
			}
			ch <- *peerAddr
		}
	}()

	go func() {
		var qp mdns.QueryParam
		defer ticker.Stop()
		for {
			qp = mdns.QueryParam{
				Domain:              "local",
				Entries:             entries,
				Service:             service,
				Timeout:             time.Second,
				WantUnicastResponse: true,
			}
			if err := mdns.Query(&qp); err != nil {
				// TODO: handle this error better
				log.Error("mdns query error:", err)
			}

			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				close(entries)
				close(ch)
				srv.Shutdown()
				return
			}
		}
	}()
	// handles query translation
	return ch, nil
}

// DiscoverOnce will run an mDNS query once and return a channel of peer
// addresses.
func DiscoverOnce(node peer.ID, service string) (<-chan peer.AddrInfo, error) {
	var (
		entries = make(chan *mdns.ServiceEntry, 32)
		ch      = make(chan peer.AddrInfo)
	)
	go func() {
		defer close(ch)
		for e := range entries {
			peer, err := mDNSEntryToAddr(e)
			if err != nil {
				log.Debug("mDNS entry to peer address:", err)
				continue
			}
			if peer.ID == node {
				continue
			}
			ch <- *peer
		}
	}()

	qp := mdns.QueryParam{
		Domain:              "local",
		Entries:             entries,
		Service:             service,
		Timeout:             time.Second / 2,
		WantUnicastResponse: false,
	}
	go func() {
		mdns.Query(&qp)
		close(entries)
	}()
	return ch, nil
}

func mDNSEntryToAddr(e *mdns.ServiceEntry) (*peer.AddrInfo, error) {
	peerID, err := peer.IDB58Decode(e.InfoFields[0])
	if err != nil {
		return nil, err
	}
	var ip net.IP
	if e.AddrV6 != nil {
		ip = e.AddrV6
	} else {
		ip = e.AddrV4
	}
	maddr, err := manet.FromNetAddr(&net.TCPAddr{
		IP:   ip,
		Port: e.Port,
	})
	if err != nil {
		return nil, err
	}
	return &peer.AddrInfo{
		ID:    peerID,
		Addrs: []multiaddr.Multiaddr{maddr},
	}, nil
}

func getDialableListenAddrs(ph host.Host) ([]*net.TCPAddr, error) {
	var out []*net.TCPAddr
	addrs, err := ph.Network().InterfaceListenAddresses()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		na, err := manet.ToNetAddr(addr)
		if err != nil {
			continue
		}
		tcp, ok := na.(*net.TCPAddr)
		if ok {
			out = append(out, tcp)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("failed to find good external addr from peerhost")
	}
	return out, nil
}

func newMDNSServer(node host.Host, service string) (*mdns.Server, error) {
	port := 5002
	addrs, err := getDialableListenAddrs(node)
	ips := make([]net.IP, 0, len(addrs))
	if err == nil {
		port = addrs[0].Port
		for _, addr := range addrs {
			// if addr.IP.IsLoopback() {
			// 	continue
			// }
			ips = append(ips, addr.IP)
		}
	}

	id := node.ID().Pretty()
	mdnsService, err := mdns.NewMDNSService(
		id, service, "", "",
		port,
		ips,
		// always give the peer id as the first info field
		[]string{id},
	)
	if err != nil {
		return nil, err
	}
	return mdns.NewServer(&mdns.Config{
		Zone:              mdnsService,
		LogEmptyResponses: false,
	})
}

func findListenableAddrs() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			// skip loopback addresses
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			// skip if the interface is down
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ip net.IP
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPAddr:
				ip = a.IP
			case *net.IPNet:
				ip = a.IP
			case *net.TCPAddr:
				ip = a.IP
			case *net.UDPAddr:
				ip = a.IP
			}
			ips = append(ips, ip)
		}
	}

	l := len(ips)
	if l == 0 {
		return nil, errors.New("could not find ip addresses")
	}
	// reverse the list
	ipAddrs := make([]net.IP, l)
	for i := l - 1; i >= 0; i-- {
		ipAddrs[i] = ips[l-i-1]
	}
	return ipAddrs, nil
}

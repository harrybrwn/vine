package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/harrybrwn/mdns"
	"github.com/harrybrwn/vine/internal/logging"
	"github.com/jackpal/gateway"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/miekg/dns"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/sirupsen/logrus"
)

// DiscoveredPeer is a peer that has been found
// in network discovery.
type DiscoveredPeer struct {
	ID        peer.ID
	Addrs     []multiaddr.Multiaddr
	ConnState network.Connectedness
}

const deadMessage = "dead"

var log = logrus.StandardLogger()

// DisableLogging will disable logging
func DisableLogging() {
	log.SetLevel(logrus.FatalLevel)
	log.SetOutput(io.Discard)
	log.Hooks = nil
}

// Logger returns the logger
func Logger() *logrus.Logger {
	return log
}

// Discovery is a discovery struct that holds discovery parameters
type Discovery struct {
	Host       host.Host
	Service    string
	Duration   time.Duration
	ListenAddr net.IP
}

// Start will start the discovery goroutine and return a channel
// of discovered addresses
func (d *Discovery) Start() (<-chan peer.AddrInfo, error) {
	return d.StartContext(context.Background())
}

// StartContext will start a mdns discovery service that
// will send new peers down the channel
func (d *Discovery) StartContext(ctx context.Context) (<-chan peer.AddrInfo, error) {
	log := logging.Copy()
	log.Formatter = &logging.PrefixedFormatter{Prefix: "DISCOVERY"}

	var (
		err error
	)
	if d.ListenAddr == nil {
		// find the default gateway ip
		d.ListenAddr, err = gateway.DiscoverInterface()
		if err != nil {
			return nil, err
		}
	}
	var (
		ch      = make(chan peer.AddrInfo)
		timer   = time.NewTimer(d.Duration)
		entries = make(chan *mdns.ServiceEntry, 32)
	)

	zone, err := newMDNSService(d.Host, d.Service, d.ListenAddr)
	if err != nil {
		return nil, err
	}
	conf := mdns.Config{
		Zone:              zone,
		LogEmptyResponses: false,
		Iface:             interfaceOrNil(d.ListenAddr),
	}
	srv, err := mdns.NewServer(&conf)
	log.WithFields(logrus.Fields{
		"interface": conf.Iface.Name,
		"mac":       conf.Iface.HardwareAddr,
		"ip":        zone.IPs,
		"port":      zone.Port,
	}).Debug("created mdns server and client")

	// handles the mDNS queries and shutdown
	go func() {
		for e := range entries {
			peerEntry, err := mDNSEntryToAddr(e)
			if err != nil {
				log.Debugf("mDNS entry to peer address failed: %v", err)
				continue
			}
			logs := map[string]interface{}{
				"host": e.Host, "port": e.Port,
				"ipv4": e.AddrV4, "ipv6": e.AddrV6,
				"state": peerEntry.ConnState,
				"name":  e.Name,
				"addrs": peerEntry.Addrs,
			}
			log.WithFields(logs).Trace("received mdns")
			if peerEntry.ConnState != network.Connected {
				log.WithFields(logs).Warn("client disconnected")
			}
			ch <- peer.AddrInfo{
				ID:    peerEntry.ID,
				Addrs: peerEntry.Addrs,
			}
		}
	}()

	go func() {
		var qp mdns.QueryParam
		defer timer.Stop()
		for {
			extra := rand.Int63n(int64(d.Duration))
			timer.Reset(d.Duration + time.Duration(extra))
			qp = mdns.QueryParam{
				Domain:              "local",
				Entries:             entries,
				Service:             d.Service,
				Timeout:             time.Second,
				WantUnicastResponse: true,
			}
			if err := mdns.Query(&qp); err != nil {
				// TODO: handle this error better
				log.Errorf("mdns query error: %v", err)
			}

			select {
			case <-timer.C:
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

type lockableService struct {
	service *mdns.MDNSService
	mu      sync.Mutex
}

func (ls *lockableService) Records(q dns.Question) []dns.RR {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.service.Records(q)
}

// DiscoverOnce will run an mDNS query once and return a channel of peer
// addresses.
func DiscoverOnce(self peer.ID, service string) (<-chan peer.AddrInfo, error) {
	var (
		entries = make(chan *mdns.ServiceEntry, 32)
		ch      = make(chan peer.AddrInfo)
	)
	log := logging.Copy()
	log.Formatter = &logging.PrefixedFormatter{Prefix: "DISCOVERY"}
	go func() {
		defer close(ch)
		for e := range entries {
			p, err := mDNSEntryToAddr(e)
			if err != nil {
				log.Debug("mDNS entry to peer address:", err)
				continue
			}
			if p.ID == self {
				continue
			}
			ch <- peer.AddrInfo{
				ID:    p.ID,
				Addrs: p.Addrs,
			}
		}
	}()

	qp := mdns.QueryParam{
		Domain:              "local",
		Entries:             entries,
		Service:             service,
		Timeout:             time.Second / 2,
		WantUnicastResponse: true,
	}
	go func() {
		mdns.Query(&qp)
		close(entries)
	}()
	return ch, nil
}

func mDNSEntryToAddr(e *mdns.ServiceEntry) (*DiscoveredPeer, error) {
	peerID, err := peer.Decode(e.InfoFields[0])
	if err != nil {
		return nil, err
	}
	var (
		ip    net.IP
		state network.Connectedness = network.Connected
	)
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

	// if there are other messages in the info
	// and the second one is the disconnected marker
	// then we set the current peer state to
	// "not connected"
	if len(e.InfoFields) > 1 && e.InfoFields[1] == deadMessage {
		state = network.NotConnected
	}
	return &DiscoveredPeer{
		ID:        peerID,
		Addrs:     []multiaddr.Multiaddr{maddr},
		ConnState: state,
	}, nil
}

func newMDNSService(node host.Host, service string, broadcastIP net.IP) (*mdns.MDNSService, error) {
	var (
		// TODO find out were to get a default port that isn't this
		port      = 5002
		ips       = make([]net.IP, 0)
		localhost = net.ParseIP("127.0.0.1")
	)

	// Now we need to know what ports the host wants
	// to listen on
	addrs, err := getDialableListenAddrs(node)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if bytes.Compare(a.IP, broadcastIP) == 0 {
			port = a.Port
			ips = append(ips, a.IP)
		} else if bytes.Compare(a.IP, localhost) == 0 {
			port = a.Port
			ips = append(ips, a.IP)
		} else {
			log.WithFields(
				logrus.Fields{"ip": a.IP, "port": a.Port},
			).Trace("ignoring address for mDNS broadcasts")
		}
	}
	if len(ips) == 0 {
		ips = append(ips, net.ParseIP("127.0.0.1"))
		log.Warnf("listen address not found, defaulting to %s", ips[0])
	}

	id := node.ID().Pretty()
	mdnsService, err := mdns.NewMDNSService(
		id, service, "", "",
		port, ips,
		[]string{id}, // always give the peer id as the first info field
	)
	if err != nil {
		return nil, err
	}
	return mdnsService, nil
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
		switch v := na.(type) {
		case *net.TCPAddr:
			out = append(out, v)
		default:
			return nil, fmt.Errorf("p2p.getDialableListenAddrs: wrong address type %T", v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("failed to find good external addr from peerhost")
	}
	return out, nil
}

func interfaceOrNil(ip net.IP) *net.Interface {
	ifi, _ := interfaceLookup(ip)
	return ifi
}

func interfaceLookup(ip net.IP) (*net.Interface, error) {
	var ifi = &net.Interface{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPNet:
				if bytes.Compare(a.IP, ip) == 0 {
					*ifi = i
					return ifi, nil
				}
			}
		}
	}
	return nil, errors.New("could not find interface")
}

func isListenableInterface(i *net.Interface) bool {
	// If the interface is a loopback interace we don't want it
	if i.Flags&net.FlagLoopback != 0 {
		return false
	}
	// false if the interface is down
	if i.Flags&net.FlagUp == 0 {
		return false
	}
	if i.Name == "docker0" {
		// TODO this is pretty hacky, probably fix this bc it migh break
		// anything running inside a docker container
		return false
	}
	// if there are no addresses return false
	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return false
	}
	return true
}

type addressMap map[[16]byte]struct{}

func (am addressMap) Has(ip net.IP) bool {
	var b [16]byte
	copy(b[:], ip)
	_, ok := am[b]
	return ok
}

func (am addressMap) put(ip net.IP) {
	var b [16]byte
	copy(b[:], ip)
	am[b] = struct{}{}
}

func badAddresses() (addressMap, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	m := make(addressMap)
	for _, i := range ifaces {
		if isListenableInterface(&i) {
			// we are only collecting the bad addresses
			continue
		}
		// add to map
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				fmt.Println([]byte(v.IP))
				var b [16]byte
				copy(b[:], v.IP)
				m[b] = struct{}{}
			default:
				continue
			}
		}
	}
	return m, nil
}

func findListenableAddrs() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0)
	for _, iface := range interfaces {
		if !isListenableInterface(&iface) {
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

func isV4(ip [16]byte) bool {
	// when ipv4 is converted to a 16 byte slice,
	// the first 10 bytes are equal to zero.
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}

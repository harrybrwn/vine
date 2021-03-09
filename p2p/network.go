package p2p

import (
	"errors"
	"net"
	"syscall"
)

func findTCPListener(listenIP net.IP) (l *net.TCPListener, p int, err error) {
	for p = 1024; p < 1<<16; p++ {
		l, err = net.ListenTCP(
			"tcp",
			&net.TCPAddr{IP: listenIP, Port: p},
		)
		switch {
		case err == nil:
			return
		case errors.Is(err, syscall.EADDRINUSE):
			continue
		}

	}
	return nil, 0, errors.New("could not find listener")
}

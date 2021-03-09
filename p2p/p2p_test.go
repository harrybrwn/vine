package p2p

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"

	"github.com/libp2p/go-libp2p"
)

func Test(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		t.Fatal(err)
	}
	ip := ips[0]
	for i := 0; i < 100; i++ {
		host, err := os.Hostname()
		if err != nil {
			t.Fatal(err)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range ips {
			if bytes.Compare(a, ip) != 0 {
				t.Fatal("differing ips", a, ip)
			}
		}
	}
}

func TestWithHost(t *testing.T) {
	t.Skip()
	h, err := libp2p.New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Error("nil host")
	}
}

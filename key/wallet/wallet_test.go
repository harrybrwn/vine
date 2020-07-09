package wallet

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/harrybrwn/go-ledger/key"
	"github.com/mr-tron/base58"
)

func TestWallet(t *testing.T) {
	w := New(Version1)
	addr := w.Address()
	if addr[0] != '1' {
		t.Error("wrong version")
	}
	publicKeyHash := w.PubKeyHash()
	if bytes.Compare(key.ExtractPubKeyHash(addr), publicKeyHash) != 0 {
		t.Error("PubKeyHash did not get the correct public key hash")
	}
	if ValidAddress("onetwothreefour") {
		t.Error("this address should probably not be valid")
	}
	if !ValidAddress(addr) {
		t.Error("address should be valid")
	}
}

func Test(t *testing.T) {
	t.Skip("only for temporary testing")
	w := New(Version1)
	pubkh := w.PubKeyHash()

	var b [25]byte
	b[0] = w.version
	fmt.Printf("%x\n", b)
	copy(b[1:], pubkh)
	fmt.Printf("%x\n", b)
	checksum := checksum(b[:21])

	copy(b[21:], checksum)
	fmt.Printf("%s%x\n", strings.Repeat(" ", 42), checksum)
	fmt.Printf("  %x\n", pubkh)
	fmt.Printf("%x\n", b)
	fmt.Println(base58.Encode(b[:]))
	fmt.Println(w.Address())

	println()
	pub := key.ExtractPubKeyHash(w.Address())
	fmt.Printf("%x\n", pubkh)
	fmt.Printf("%x\n", pub)
}

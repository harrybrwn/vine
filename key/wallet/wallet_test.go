package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"testing"

	"github.com/harrybrwn/go-ledger/key"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/mr-tron/base58"
)

func TestWallet(t *testing.T) {
	w := New()
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
	w := New()
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

func TestReadWrite(t *testing.T) {
	check := func(e error) {
		if e != nil {
			t.Error(e)
		}
	}
	var buf bytes.Buffer
	w := New()
	w.version = 0x3
	_, err := w.WriteTo(&buf)
	check(err)
	wt := Wallet{}
	_, err = wt.ReadFrom(&buf)
	check(err)
	if w.Address() != wt.Address() {
		t.Error("address was changed after reading/writing wallet")
	}
	if w.priv.X.Cmp(wt.priv.X) != 0 {
		t.Error("private key X was changed")
	}
	if w.priv.Y.Cmp(wt.priv.Y) != 0 {
		t.Error("private key Y was changed")
	}
	k := w.privKey()
	k2 := wt.privKey()
	if !k.Equals(k2) {
		t.Error("wallet privet keys different when changed to a crypto key")
	}
	if w.version != wt.version {
		t.Error("wrong version")
	}
}

func dec(k *ecdsa.PrivateKey) crypto.PrivKey {
	p, _, _ := crypto.ECDSAKeyPairFromKey(k)
	return p
}

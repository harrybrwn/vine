package key

import (
	"bytes"
	"testing"
)

func TestGenPair(t *testing.T) {
	pub, priv := GenPair()
	if pub == nil || priv == nil {
		t.Error("nil keys")
	}
	if len(pub) != 64 {
		t.Error("should be 64 bytes long")
	}
}

func TestExtract(t *testing.T) {
	addr := "12FkDpnwMHu9awdCC6EYLigJTFUFkwVcYy"
	pubkey := []byte{49, 21, 124, 208, 172, 116, 197, 18, 240, 146, 95, 196, 23, 7, 115, 136, 35, 146, 200, 227, 229, 188, 160, 84, 29, 5, 80, 237, 47, 108, 176, 96, 74, 111, 66, 231, 8, 53, 84, 125, 185, 33, 160, 70, 9, 249, 127, 129, 77, 149, 27, 146, 73, 173, 237, 201, 133, 78, 230, 194, 9, 78, 15, 250}

	if bytes.Compare(PubKey(pubkey).Hash(), ExtractPubKeyHash(addr)) != 0 {
		t.Error("address should contain public key hash")
	}
	a := address(addr)
	if bytes.Compare(a.PubKeyHash(), PubKey(pubkey).Hash()) != 0 {
		t.Error("should have generated the same public key hash")
	}
	if a.Address() != addr {
		t.Error("expected the same address")
	}
	r := NewReceiver(addr)
	if r.Address() != a.Address() || r.Address() != addr {
		t.Error("expected the same address")
	}
}

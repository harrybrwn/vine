package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	mathrand "math/rand"
	"testing"

	"github.com/harrybrwn/vine/key/wallet"
)

// Toggle deterministic mode for some
// testing setup functions.
var Deterministic = false

func Wallet(t *testing.T, seed int64) *wallet.Wallet {
	t.Helper()
	if !Deterministic {
		// if we are not in deterministic mode,
		// create a random wallet
		return wallet.New()
	}
	gen := mathrand.New(mathrand.NewSource(seed))
	key, err := ecdsa.GenerateKey(elliptic.P256(), gen)
	if err != nil {
		t.Fatal(err)
	}
	return wallet.FromKey(key)
}

type Block interface {
	GetHash() []byte
	GetTransactions()
}

type Input interface {
	GetOutIndex() int32
	GetPubKey() []byte
	GetSignature() []byte
	GetTxID() []byte
}

type Output interface {
	GetAmount() uint64
	GetPubKeyHash() []byte
}

package key

import (
	"crypto/ecdsa"
)

// Addressable defines an interface for
// objects that hold an address
type Addressable interface {
	Address() string
}

// Receiver defines an interface for objects that
// are able to receive the contents of a transaction
type Receiver interface {
	Addressable
	PubKeyHash() []byte
}

// Sender defines an interface for
// somthing that can send values through
// a transaction. This should be analogous to
// the current user.
type Sender interface {
	Receiver
	PrivateKey() *ecdsa.PrivateKey
	PublicKey() []byte
}

// NewReceiver creates a receiver type
func NewReceiver(addr string) Receiver {
	return address(addr)
}

// Address is an address
type address string

func (a address) PubKeyHash() []byte {
	return ExtractPubKeyHash(string(a))
}

func (a address) Address() string {
	return string(a)
}

type sender struct {
	priv *ecdsa.PrivateKey
	pub  PubKey
}
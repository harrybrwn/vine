package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
)

type Key interface {
	Bytes() []byte
	Eq(Key) bool
}

type PrivKey interface {
	Key
	Sign([]byte) ([]byte, error)
	Pub()
}

// TODO: change this to PubKey
type PublicKey interface {
	Key
}

// GenPair generates a public key and private key pair
func GenPair() ([]byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil
	}
	pub := bytes.Join([][]byte{
		priv.PublicKey.X.Bytes(),
		priv.PublicKey.Y.Bytes(),
	}, nil)
	return pub, priv
}

// ExtractPubKeyHash will pull the public key hash out of
// a wallet address.
func ExtractPubKeyHash(address string) []byte {
	hash, err := base58.Decode(address)
	if err != nil {
		return nil
	}
	return hash[1 : len(hash)-4]
}

// PublicKey is a public key
type PubKey []byte

// Hash will generate the public key hash.
func (pk PubKey) Hash() []byte {
	pubhash := sha256.Sum256(pk)
	ripemd := ripemd160.New()
	ripemd.Write(pubhash[:])
	return ripemd.Sum(nil)
}

func (pk PubKey) Bytes() []byte {
	return []byte(pk)
}

func (pk PubKey) Eq(k Key) bool {
	return bytes.Compare(pk.Bytes(), k.Bytes()) == 0
}

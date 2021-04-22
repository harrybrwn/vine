package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
)

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

// GenKey will genrate a private key
func GenKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	return priv
}

func UnmarshalPubKey(b []byte) (*ecdsa.PublicKey, error) {
	pubi, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	pub, ok := pubi.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return pub, nil
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

// HashPubKey will create a public key hash
// from a public key.
func HashPubKey(pub crypto.PubKey) []byte {
	raw, err := pub.Raw()
	if err != nil {
		return nil
	}
	return rawPubKeyHash(raw)
}

func HashECDSAPubKey(pub *ecdsa.PublicKey) []byte {
	raw, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return rawPubKeyHash(raw)
}

func rawPubKeyHash(b []byte) []byte {
	ripemd := ripemd160.New()
	pubhash := sha256.Sum256(b)
	_, err := ripemd.Write(pubhash[:])
	if err != nil {
		return nil
	}
	return ripemd.Sum(nil)
}

// PubKey is a public key
type PubKey []byte

// Hash will generate the public key hash.
func (pk PubKey) Hash() []byte {
	pubhash := sha256.Sum256(pk)
	ripemd := ripemd160.New()
	ripemd.Write(pubhash[:])
	return ripemd.Sum(nil)
}

func (pk PubKey) Raw() ([]byte, error) {
	return []byte(pk), nil
}
func (pk PubKey) Bytes() ([]byte, error) {
	return []byte(pk), nil
}

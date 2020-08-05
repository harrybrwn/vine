package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"io"

	"github.com/harrybrwn/go-ledger/key"
	"github.com/mr-tron/base58"
)

// Version1 is address version 1
const Version1 byte = 0x00

// New creates a new wallet with the default version.
func New() *Wallet {
	pub, priv := key.GenPair()
	return &Wallet{
		pub:     pub,
		priv:    priv,
		version: Version1,
	}
}

// Versioned will create a new wallet with a given
// version number.
func Versioned(v byte) *Wallet {
	pub, priv := key.GenPair()
	return &Wallet{
		pub:     pub,
		priv:    priv,
		version: v,
	}
}

// Wallet is a digital wallet containing a
// public key and private key
type Wallet struct {
	pub     key.PubKey
	priv    *ecdsa.PrivateKey
	version byte
}

const (
	checksumLength = 4
	versionLength  = 1
	addressLength  = versionLength + 20 + checksumLength
)

// PublicKey return's the wallet's public key
func (w *Wallet) PublicKey() []byte {
	return w.pub
}

// PrivateKey returns the wallet's private key
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.priv
}

// Address will create a wallet address from the wallet's
// public key.
func (w *Wallet) Address() string {
	// | v |        Private Key        |
	// | v |      X      |      Y      |
	// | v |        Public Key         |
	// | v | ripemd160(sha256(pubkey)) |           checksum        |
	// | v | public key hash  (pubkh)  | sha256(sha256(pubkh))[:4] |
	// | 1 |            20             |             4             |
	var addresshash [addressLength]byte
	addresshash[0] = w.version
	pubkh := w.pub.Hash()
	copy(addresshash[versionLength:], pubkh)
	copy(addresshash[21:], checksum(addresshash[:21]))
	return base58.Encode(addresshash[:])
}

// ValidAddress will return true if the address
// given is a valid wallet address
func ValidAddress(address string) bool {
	dec, err := base58.Decode(address)
	if err != nil {
		return false
	}
	len := len(dec)
	if len != 25 {
		return false
	}
	v, pubkh, chksum := dec[0], dec[1:len-4], dec[len-4:]
	targetChksum := checksum(append([]byte{v}, pubkh...))
	// compare the two checksums
	for i := 0; i < checksumLength; i++ {
		if targetChksum[i] != chksum[i] {
			return false
		}
	}
	return true
}

// PubKeyHash will generate the hash for
// the wallet's public key
func (w *Wallet) PubKeyHash() []byte {
	return w.pub.Hash()
}

// WriteTo will serialize the wallet and write it to an io.Writer
func (w *Wallet) WriteTo(wr io.Writer) (int64, error) {
	type wallet struct {
		Pub  key.PubKey
		Priv *ecdsa.PrivateKey
		V    byte
	}
	wlt := wallet{Pub: w.pub, Priv: w.priv, V: w.version}
	return 0, gob.NewEncoder(wr).Encode(&wlt)
}

func init() {
	gob.Register(elliptic.P256())
}

// ReadFrom will populate the wallet data by reading from an io.Reader
func (w *Wallet) ReadFrom(r io.Reader) (int64, error) {
	type wallet struct {
		Pub  key.PubKey
		Priv *ecdsa.PrivateKey
		V    byte
	}
	wlt := wallet{}
	err := gob.NewDecoder(r).Decode(&wlt)
	if err != nil {
		return 0, err
	}
	w.pub = wlt.Pub
	w.priv = wlt.Priv
	w.version = wlt.V
	return 0, nil
}

func checksum(b []byte) []byte {
	passone := sha256.Sum256(b)
	passtwo := sha256.Sum256(passone[:])
	return passtwo[:checksumLength]
}

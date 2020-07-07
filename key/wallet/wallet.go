package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"

	"github.com/harrybrwn/blockchain/key"
	"github.com/mr-tron/base58"
)

// Version1 is address version 1
const Version1 byte = 0x00

// New creates a new wallet
func New(version byte) *Wallet {
	pub, priv := key.GenPair()
	return &Wallet{
		pub:     pub,
		priv:    priv,
		version: version,
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

func checksum(b []byte) []byte {
	passone := sha256.Sum256(b)
	passtwo := sha256.Sum256(passone[:])
	return passtwo[:checksumLength]
}

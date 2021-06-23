package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strconv"

	"github.com/harrybrwn/vine/key"
	"github.com/libp2p/go-libp2p-core/crypto"
	crypto_pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
)

// Version1 is address version 1
const Version1 byte = 0x00

// New creates a new wallet with the default version.
func New() *Wallet {
	_, priv := key.GenPair()
	privkey, _, _ := crypto.ECDSAKeyPairFromKey(priv)
	return &Wallet{
		priv:    priv,
		version: Version1,
		privkey: privkey,
	}
}

// Versioned will create a new wallet with a given
// version number.
func Versioned(v byte) *Wallet {
	_, priv := key.GenPair()
	privkey, _, _ := crypto.ECDSAKeyPairFromKey(priv)
	return &Wallet{
		priv:    priv,
		version: v,
		privkey: privkey,
	}
}

// FromKey will create a wallet from an ecdsa private key
func FromKey(priv *ecdsa.PrivateKey) *Wallet {
	cryptoPriv, _, _ := crypto.ECDSAKeyPairFromKey(priv)
	return &Wallet{
		priv:    priv,
		privkey: cryptoPriv,
		version: Version1,
	}
}

// Wallet is a digital wallet containing a
// public key and private key
type Wallet struct {
	priv    *ecdsa.PrivateKey
	version byte

	// just for compatability with libp2p's crypto package
	privkey crypto.PrivKey
}

const (
	checksumLength = 4
	versionLength  = 1
	addressLength  = versionLength + 20 + checksumLength
)

// PublicKey return's the wallet's public key
func (w *Wallet) PublicKey() []byte {
	raw, err := x509.MarshalPKIXPublicKey(&w.priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return raw
}

// PrivateKey returns the wallet's private key
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.priv
}

// Address will create a wallet address from the wallet's
// public key.
func (w *Wallet) Address() string {
	// | v |        Public Key         |
	// | v |      X      |      Y      |
	// | v | ripemd160(sha256(pubkey)) |           checksum        |
	// | v | public key hash  (pubkh)  | sha256(sha256(pubkh))[:4] |
	// | 1 |            20             |             4             |
	var addresshash [addressLength]byte
	addresshash[0] = w.version
	pubkh := key.HashECDSAPubKey(&w.priv.PublicKey)
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
	return key.HashECDSAPubKey(&w.priv.PublicKey)
}

type serializablePrivateKey struct {
	V    byte
	Priv *ecdsa.PrivateKey
}

// WriteTo will serialize the wallet and write it to an io.Writer
func (w *Wallet) WriteTo(wr io.Writer) (int64, error) {
	enc, err := x509.MarshalECPrivateKey(w.priv)
	if err != nil {
		return 0, err
	}
	return 1, pem.Encode(wr, &pem.Block{
		Type:  "private-key",
		Bytes: enc,
		Headers: map[string]string{
			"version": strconv.FormatUint(uint64(w.version), 16)},
	})
}

// ReadFrom will populate the wallet data by reading from an io.Reader
func (w *Wallet) ReadFrom(r io.Reader) (int64, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(r)
	if err != nil {
		return 0, err
	}
	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		return 0, errors.New("no block found")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return 0, err
	}
	w.priv = priv
	w.privkey, _, err = crypto.ECDSAKeyPairFromKey(priv)
	if err != nil {
		return 0, err
	}
	v, ok := block.Headers["version"]
	if ok && len(v) > 0 {
		version, err := strconv.ParseUint(v, 16, 8)
		if err != nil {
			return 0, err
		}
		w.version = byte(version)
	}
	return n, nil
}

func checksum(b []byte) []byte {
	passone := sha256.Sum256(b)
	passtwo := sha256.Sum256(passone[:])
	return passtwo[:checksumLength]
}

func walletPubKeyHash(pubkey []byte) []byte {
	pubhash := sha256.Sum256(pubkey)
	ripemd := ripemd160.New()
	ripemd.Write(pubhash[:])
	return ripemd.Sum(nil)
}

var _ crypto.PrivKey = (*Wallet)(nil)

// GetPublic gets the public key
func (w *Wallet) GetPublic() crypto.PubKey {
	return w.privKey().GetPublic()
}

// PrivKey will get the crypto.PrivKey for libp2p compatibility
func (w *Wallet) privKey() crypto.PrivKey {
	var err error
	if w.privkey == nil {
		w.privkey, _, err = crypto.ECDSAKeyPairFromKey(w.priv)
		if err != nil {
			panic(err)
		}
	}
	return w.privkey
}

// Type returns the type of key that the wallet has
func (w *Wallet) Type() crypto_pb.KeyType {
	return w.privKey().Type()
}

// Sign will sign a byte array with the private key
func (w *Wallet) Sign(b []byte) ([]byte, error) {
	return w.privKey().Sign(b)
}

// Raw gets the raw data
func (w *Wallet) Raw() ([]byte, error) {
	return w.privKey().Raw()
}

// Equals returns true if the key pass is the same key
func (w *Wallet) Equals(k crypto.Key) bool {
	return w.privKey().Equals(k)
}

// Bytes get gets the raw bytes of the key
func (w *Wallet) Bytes() ([]byte, error) {
	return w.privKey().Bytes()
}

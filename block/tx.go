package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/harrybrwn/vine/key"
)

// ErrInvalidSignature is the error value given when a transaction has
// an invalid signature
var ErrInvalidSignature = errors.New("invalid signature")

var coinbaseValue uint64 = 100

// Coinbase will create a coinbase transaction.
func Coinbase(to key.Address) *Transaction {
	tx := &Transaction{
		Inputs: []*TxInput{
			{
				TxID:      nil,
				OutIndex:  -1,
				Signature: nil,
				PubKey:    nil,
			},
		},
		Outputs: []*TxOutput{
			{
				Amount:     coinbaseValue,
				PubKeyHash: key.ExtractPubKeyHash(to.Address()),
			},
		},
	}
	tx.ID = tx.hash()
	return tx
}

// TxDesc describes a transaction at a high level
type TxDesc struct {
	From   key.Sender
	To     key.Receiver
	Amount uint64
}

type receiver struct {
	to     key.Receiver
	amount uint64
}

// NewTransaction creates a new transaction. The new transaction will not be
// added to the chain.
func NewTransaction(finder TxFinder, stats UTXOSet, descriptor TxDesc) (*Transaction, error) {
	tx := &Transaction{
		ID:      nil,
		Lock:    ptypes.TimestampNow(),
		Inputs:  make([]*TxInput, 0, 1),
		Outputs: make([]*TxOutput, 0, 1),
	}
	err := initTransaction(stats, tx, descriptor)
	if err != nil {
		return nil, err
	}
	tx.Lock = ptypes.TimestampNow()
	return tx, tx.Sign(descriptor.From.PrivateKey(), finder)
}

func initTransaction(
	stats UTXOSet,
	tx *Transaction,
	header TxDesc,
) (err error) {
	var (
		bal = stats.Bal(header.From)
		// spending is the total output being used up in transaction
		// including any amount that will be returned to the sender
		// as change in an additional output
		spending uint64
	)
	if header.Amount > bal {
		return ErrNotEnoughFunds
	}

	utxouts := FindOutputsToSpend(stats, header.From, header.Amount)

	for _, o := range utxouts {
		tx.Inputs = append(tx.Inputs, &TxInput{
			TxID:      o.txid,
			OutIndex:  int32(o.index),
			PubKey:    header.From.PublicKey(),
			Signature: nil,
		})
		spending += o.Amount
	}

	outs, err := newOutputs(
		header.From, spending,
		[]TxDesc{header},
	)
	if err != nil {
		return err
	}
	tx.Outputs = append(tx.Outputs, outs...)
	tx.ID = tx.hash()
	return nil
}

// create a transaction. ignores the from field in all elements of the recv argument
func createTx(stats *chainStats, from key.Sender, recv []TxDesc) (*Transaction, error) {
	var (
		tx = &Transaction{
			ID:      nil,
			Lock:    ptypes.TimestampNow(),
			Inputs:  make([]*TxInput, 0, 1),
			Outputs: make([]*TxOutput, 0, 1),
		}
		// Sender's balance
		bal = stats.Bal(from)
		// Total amount the transacton initiator wants to spend
		needed uint64
		// spending is the total output being used up in transaction
		// including any amount that will be returned to the sender
		// as change in an additional output
		spending uint64
	)
	for _, r := range recv {
		needed += r.Amount
	}
	if needed > bal {
		return nil, ErrNotEnoughFunds
	}
	utxouts := FindOutputsToSpend(stats, from, needed)

	for _, o := range utxouts {
		tx.Inputs = append(tx.Inputs, &TxInput{
			TxID:      o.txid,
			OutIndex:  int32(o.index),
			PubKey:    from.PublicKey(),
			Signature: nil,
		})
		spending += o.Amount
	}
	outs, err := newOutputs(from, spending, recv)
	if err != nil {
		return nil, err
	}
	tx.Outputs = append(tx.Outputs, outs...)
	tx.ID = tx.hash()
	return tx, nil
}

func newOutputs(from key.Sender, balance uint64, recv []TxDesc) ([]*TxOutput, error) {
	var (
		n    = len(recv)
		outs = make([]*TxOutput, 0, n)
	)
	// Add a transaction output for each receiver
	for i := 0; i < n; i++ {
		balance -= recv[i].Amount
		if balance < 0 {
			return nil, ErrNotEnoughFunds
		}
		outs = append(outs, &TxOutput{
			Amount:     recv[i].Amount,
			PubKeyHash: recv[i].To.PubKeyHash(),
		})
	}
	// If the sender did not spend their entire
	// balance then an extra output is added which
	// gives the sender the rest of their balance
	if balance > 0 {
		outs = append(outs, &TxOutput{
			Amount:     balance,
			PubKeyHash: from.PubKeyHash(),
		})
	}
	return outs, nil
}

// Sign signs a tx
func (tx *Transaction) Sign(priv *ecdsa.PrivateKey, finder TxFinder) error {
	if tx.IsCoinbase() {
		return nil
	}
	var (
		txcp = proto.Clone(tx).(*Transaction)
		prev *Transaction
	)

	for i, input := range txcp.Inputs {
		prev = finder.Transaction(input.TxID)
		if prev == nil || prev.ID == nil {
			return errors.New("transaction does not exist or is malformed")
		}
		input.Signature = nil
		input.PubKey = prev.Outputs[input.OutIndex].PubKeyHash
		txHash := txcp.hash()
		input.PubKey = nil

		r, s, err := ecdsa.Sign(rand.Reader, priv, txHash)
		if err != nil {
			return err
		}
		tx.Inputs[i].Signature = bytes.Join([][]byte{r.Bytes(), s.Bytes()}, nil)
	}
	return nil
}

// VerifySig will verify that a transaction has been correctly signed
func (tx *Transaction) VerifySig(find TxFinder) error {
	if tx.IsCoinbase() {
		return nil
	}
	var (
		txcp       = proto.Clone(tx).(*Transaction)
		curve      = elliptic.P256()
		prev       *Transaction
		x, y, r, s *big.Int
		pub        ecdsa.PublicKey
		txHash     []byte
	)

	for i, input := range txcp.Inputs {
		prev = find.Transaction(input.TxID)
		txcp.Inputs[i].Signature = nil
		// set the public key to get the correct transaction hash
		txcp.Inputs[i].PubKey = prev.Outputs[input.OutIndex].PubKeyHash
		txHash = txcp.hash()
		txcp.Inputs[i].PubKey = nil

		x, y = splitBytes(tx.Inputs[i].PubKey) // get the unmodified input public key
		pub = ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		r, s = splitBytes(tx.Inputs[i].Signature)
		if !ecdsa.Verify(&pub, txHash, r, s) {
			return ErrInvalidSignature
		}
	}
	return nil
}

// GetFee will get the transaction fee for the transaction
// The transaction fee is defined as the total input value
// minus the total output value of a transaction.
func (tx *Transaction) Fee(finder TxFinder) uint64 {
	var (
		input, output uint64
	)
	for _, in := range tx.Inputs {
		ref := finder.Transaction(in.TxID)
		input += ref.Outputs[in.OutIndex].Amount
	}
	for _, out := range tx.Outputs {
		output += out.Amount
	}
	return input - output
}

func splitBytes(buf []byte) (x, y *big.Int) {
	l := len(buf)
	x, y = new(big.Int), new(big.Int)
	x.SetBytes(buf[:l/2])
	y.SetBytes(buf[l/2:])
	return
}

// IsCoinbase will return true of the transaction
// is a coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && len(tx.Outputs) == 1 && tx.Inputs[0].OutIndex < 0
}

// StrID will return a hex encoded version of the transaction ID
func (tx *Transaction) StrID() string {
	return hex.EncodeToString(tx.ID)
}

func txMerkleRoot(txs []*Transaction) ([]byte, error) {
	if len(txs) < 0 {
		return nil, nil
	}
	hashes := make([][]byte, 0, len(txs))
	hash := sha256.New()
	for _, tx := range txs {
		_, err := hash.Write(tx.hash())
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash.Sum(nil))
		hash.Reset()
	}
	return merkleroot(hashes), nil
}

func (tx *Transaction) hash() []byte {
	var (
		b [8]byte
		h = sha256.New()
	)
	for _, in := range tx.Inputs {
		h.Write(in.PubKey)
		h.Write(in.Signature)
		h.Write(in.TxID)
		binary.LittleEndian.PutUint64(b[:], uint64(in.OutIndex))
		h.Write(b[:])
	}
	for _, out := range tx.Outputs {
		h.Write(out.PubKeyHash)
		binary.LittleEndian.PutUint64(b[:], out.Amount)
		h.Write(b[:])
	}
	return h.Sum(nil)
}

func (out *TxOutput) isLockedWith(pubkeyhash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubkeyhash) == 0
}

func hexAddrKey(user key.Receiver) string {
	return hex.EncodeToString(user.PubKeyHash())
}

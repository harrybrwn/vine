package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/key"
)

// ErrInvalidSignature is the error value given when a transaction has
// an invalid signature
var ErrInvalidSignature = errors.New("invalid signature")

// UTXOSet holds unspent transaction outputs.
type UTXOSet interface {
	Bal(key.Address) int64
}

var coinbaseValue int64 = 100

// Coinbase will create a coinbase transaction.
func Coinbase(to key.Address) *Transaction {
	tx := &Transaction{
		Inputs: []*TxInput{
			{
				TxID:      []byte{},
				OutIndex:  -1,
				Signature: []byte(fmt.Sprintf("Coins to %s", to)),
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

type chainStats struct {
	// mapping of user addresses to user balances
	balances map[string]int64

	// maps transaction IDs to spent output indexes
	spent   map[string][]int
	unspent []*Transaction
	// maps user pub-key-hashes to unspent outputs
	utxo map[string][]*TxOutput
}

// TxDesc describes a transaction at a high level
type TxDesc struct {
	From   key.Sender
	To     key.Receiver
	Amount int64
}

type receiver struct {
	to     key.Receiver
	amount int64
}

// NewTransaction creates a new transaction
func NewTransaction(chain Chain, stats *chainStats, descriptor *TxDesc) (*Transaction, error) {
	tx := new(Transaction)
	err := initTransaction(chain, stats, *descriptor, tx)
	return tx, err
}

func initTransaction(
	finder TxFinder,
	stats *chainStats,
	header TxDesc,
	tx *Transaction,
) (err error) {
	bal, spendable := stats.spendableTxOutputs(header.From.PubKeyHash(), header.Amount)
	err = tx.setInputs(header.From, spendable)
	if err != nil {
		return err
	}
	outs, err := newOutputs(
		header.From, bal,
		[]receiver{{header.To, header.Amount}},
	)
	if err != nil {
		return err
	}
	tx.Outputs = append(tx.Outputs, outs...)
	tx.ID = tx.hash()
	return nil // in the future... return tx.Sign(header.From.PrivateKey(), finder)
}

func newOutputs(from key.Sender, balance int64, recv []receiver) ([]*TxOutput, error) {
	n := len(recv)
	outs := make([]*TxOutput, 0, n)
	for i := 0; i < n; i++ {
		balance -= recv[i].amount
		if balance < 0 {
			return nil, ErrNotEnoughFunds
		}
		outs = append(outs, &TxOutput{
			Amount:     recv[i].amount,
			PubKeyHash: recv[i].to.PubKeyHash(),
		})
	}
	if balance > 0 {
		outs = append(outs, &TxOutput{
			Amount:     balance,
			PubKeyHash: from.PubKeyHash(),
		})
	}
	return outs, nil
}

func buildChainStats(it Iterator) *chainStats {
	var (
		block   *Block
		userkey string
		s       = &chainStats{
			balances: make(map[string]int64),
			spent:    make(map[string][]int),
			unspent:  make([]*Transaction, 0),
			utxo:     make(map[string][]*TxOutput),
		}
	)

	for {
		block = it.Next()
		for _, tx := range block.Transactions {
			txid := tx.StrID()
			for outIx, out := range tx.Outputs {
				// check if the current transaction output index
				// has been stored in the spent tx outputs
				if s.txOutputIsSpent(txid, outIx) {
					continue
				}

				// If the output has not been referenced by a previous input
				// then we can add it the unspent transaction outputs and
				// count the amount sent to that public key hash.
				userkey = hex.EncodeToString(out.PubKeyHash)
				if _, ok := s.balances[userkey]; !ok {
					s.balances[userkey] = 0
				}
				// fmt.Println(userkey, s.balances[userkey], "+", out.Amount)
				s.balances[userkey] += out.Amount
				s.unspent = append(s.unspent, tx)
				s.utxo[userkey] = append(s.utxo[userkey], out)
			}

			// Inputs of a coinbase transactions do not reference an output.
			// https://en.bitcoin.it/wiki/Transaction#Generation
			if !tx.IsCoinbase() {
				for _, in := range tx.Inputs {
					s.markSpent(in.TxID, int(in.OutIndex))
				}
			}
		}
		if IsGenisis(block) {
			if ic, ok := it.(io.Closer); ok {
				ic.Close()
			}
			break
		}
	}
	return s
}

func (sts *chainStats) markSpent(txid []byte, index int) {
	id := hex.EncodeToString(txid)
	sts.spent[id] = append(sts.spent[id], index)
}

func (sts *chainStats) Bal(user key.Receiver) (bal int64) {
	pubkh := key.ExtractPubKeyHash(user.Address())
	key := hex.EncodeToString(pubkh)
	for _, out := range sts.utxo[key] {
		bal += out.Amount
	}
	if bal != sts.balances[hex.EncodeToString(user.PubKeyHash())] {
		panic("this is a test: should have gotten the same result")
	}
	return bal
}

func (sts *chainStats) UserUTXO(user key.Receiver) []*TxOutput {
	return sts.utxo[hex.EncodeToString(user.PubKeyHash())]
}

func (sts *chainStats) txOutputIsSpent(txid string, index int) bool {
	if spentouts, ok := sts.spent[txid]; ok {
		for _, ix := range spentouts {
			if ix == index {
				return true
			}
		}
	}
	return false
}

// SpendableTxOutputs returns a user's balance and spendable outputs.
// user is the user that will be spending the outputs and
// cap is the amount cap that they are trying to spend
func (sts *chainStats) spendableTxOutputs(pubkeyhash []byte, cap int64) (spendable int64, spOuts map[string][]int) {
	var (
		txid string
	)
	spOuts = make(map[string][]int)
	for _, tx := range sts.unspent {
		txid = tx.StrID()
		for oid, out := range tx.Outputs {
			if !out.isLockedWith(pubkeyhash) {
				continue
			}
			if spendable <= cap {
				spendable += out.Amount
				spOuts[txid] = append(spOuts[txid], oid)
				if spendable >= cap {
					return
				}
			}
		}
	}
	return
}

// Sign signs a tx
func (tx *Transaction) Sign(priv *ecdsa.PrivateKey, find TxFinder) error {
	if tx.IsCoinbase() {
		return nil
	}
	var (
		txcp = proto.Clone(tx).(*Transaction)
		prev *Transaction
	)

	for i, input := range txcp.Inputs {
		prev = find.Transaction(input.TxID)
		if prev == nil {
			return errors.New("transaction does not exist or is malformed")
		}
		input.Signature = nil
		if int(input.OutIndex) >= len(txcp.Outputs) {
			// TODO: fix this, at least with good error handling
			fmt.Println("outindex:", input.OutIndex, ", input len:", len(txcp.Outputs))
			fmt.Println(hex.EncodeToString(prev.ID), "=>", hex.EncodeToString(txcp.ID))
			// return errors.New("invalid transaction output index")
			panic("transaction output index is out of range: wtf is going on")
		}

		input.PubKey = txcp.Outputs[input.OutIndex].PubKeyHash
		txcp.ID = txcp.hash()
		txcp.Inputs[i].PubKey = nil
		r, s, err := ecdsa.Sign(rand.Reader, priv, txcp.ID)
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

	for i, input := range tx.Inputs {
		prev = find.Transaction(input.TxID)
		txcp.Inputs[i].Signature = nil
		// set the public key to get the correct transaction hash
		txcp.Inputs[i].PubKey = prev.Outputs[input.OutIndex].PubKeyHash
		txHash = txcp.hash()
		// reset the public key after hashing
		txcp.Inputs[i].PubKey = nil

		r, s = splitBytes(input.Signature)
		x, y = splitBytes(input.PubKey)
		pub = ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		if !ecdsa.Verify(&pub, txHash, r, s) {
			return ErrInvalidSignature
		}
	}
	return nil
}

func splitBytes(buf []byte) (x, y *big.Int) {
	l := len(buf)
	x, y = &big.Int{}, &big.Int{}
	x.SetBytes(buf[:l/2])
	y.SetBytes(buf[l/2:])
	return
}

func (tx *Transaction) setInputs(sender key.Sender, spendable map[string][]int) error {
	for txid, outIDs := range spendable {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			return err
		}
		for _, out := range outIDs {
			tx.Inputs = append(tx.Inputs, &TxInput{
				TxID:      txID,
				OutIndex:  int32(out),
				Signature: nil,
				PubKey:    sender.PublicKey(),
			})
		}
	}
	return nil
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
		raw, err := proto.Marshal(tx)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(raw)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash.Sum(nil))
		hash.Reset()
	}
	return merkleroot(hashes), nil
}

func (tx *Transaction) hash() []byte {
	b, err := proto.Marshal(tx)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func (out *TxOutput) isLockedWith(pubkeyhash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubkeyhash) == 0
}

func hexAddrKey(user key.Receiver) string {
	return hex.EncodeToString(user.PubKeyHash())
}

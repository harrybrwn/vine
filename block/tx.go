package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/key"
)

// UTXO holds unspent transaction outputs.
type UTXO interface {
	Bal(key.Addressable) int64
	Add(key.Receiver, ...*TxOutput)
}

var coinbaseValue int64 = 100

// Coinbase will create a coinbase transaction.
func Coinbase(to string) *Transaction {
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
				PubKeyHash: key.ExtractPubKeyHash(to),
			},
		},
	}
	tx.ID = tx.hash()
	return tx
}

type txHead struct {
	from   key.Sender
	to     key.Receiver
	amount int64
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

func initTransaction(finder TxFinder, stats *chainStats, header txHead, tx *Transaction) (err error) {
	bal, spendable := stats.spendableTxOutputs(header.from.PubKeyHash(), header.amount)
	err = tx.setInputs(header.from, spendable)
	if err != nil {
		return err
	}
	outs, err := newOutputs(
		header.from, bal,
		[]key.Receiver{header.to},
		[]int64{header.amount},
	)
	if err != nil {
		return err
	}
	tx.Outputs = append(tx.Outputs, outs...)
	tx.ID = tx.hash()
	return tx.Sign(header.from.PrivateKey(), finder)
}

func newOutputs(from key.Sender, balance int64, to []key.Receiver, amounts []int64) ([]*TxOutput, error) {
	n := len(to)
	if len(amounts) != n {
		return nil, errors.New("number of receivers does not match number of amounts")
	}
	outs := make([]*TxOutput, 0, n)
	for i := 0; i < n; i++ {
		balance -= amounts[i]
		if balance < 0 {
			return nil, ErrNotEnoughFunds
		}
		outs = append(outs, &TxOutput{
			Amount:     amounts[i],
			PubKeyHash: to[i].PubKeyHash(),
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
			break
		}
	}
	return s
}

func (sts *chainStats) markSpent(txid []byte, index int) {
	id := hex.EncodeToString(txid)
	sts.spent[id] = append(sts.spent[id], index)
}

func (sts *chainStats) bal(user key.Receiver) (bal int64) {
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
func (tx *Transaction) Sign(key *ecdsa.PrivateKey, find TxFinder) error {
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
			fmt.Println("outindex:", input.OutIndex, ", input len:", len(txcp.Outputs))
			fmt.Println(hex.EncodeToString(prev.ID), "=>", hex.EncodeToString(txcp.ID))
			return errors.New("invalid transaction output index")
		}

		input.PubKey = txcp.Outputs[input.OutIndex].PubKeyHash
		txcp.ID = txcp.hash()
		txcp.Inputs[i].PubKey = nil
		r, s, err := ecdsa.Sign(rand.Reader, key, txcp.ID)
		if err != nil {
			return err
		}
		txcp.Inputs[i].Signature = bytes.Join([][]byte{r.Bytes(), s.Bytes()}, nil)
	}
	return nil
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

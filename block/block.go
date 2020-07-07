//go:generate protoc --go_out=. block.proto

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
	"github.com/harrybrwn/blockchain/key"
)

// ErrNotEnoughFunds is an error returned when a sender
// does not have enough money to make a transaction
var ErrNotEnoughFunds = errors.New("not enough funds")

// Chain is an interface that defines what a
// blockchain is.
type Chain interface {
	Iter() Iterator
	// Transaction looks for a Transaction by ID
	// and returns nil if no transaction was found
	Transaction([]byte) *Transaction
}

// Iterator is an interface that defines a block iterator
// api.
type Iterator interface {
	// returns the next block in the chain, value will
	// be nil if there are no more blocks. This should
	// return the genisis block as the last block
	Next() *Block
}

// IterCloser is an Iterator that must be closed
type IterCloser interface {
	Iterator
	Close() error
}

// New creates a new block from a list of
// transactions and the previous hash
func New(txs []*Transaction, prev []byte) *Block {
	b := &Block{
		Data:         []byte("go-ledger Transaction Block"),
		Transactions: txs,
		PrevHash:     prev,
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	return b
}

// Genisis creates the first block of the chain
func Genisis(coinbase *Transaction) *Block {
	b := &Block{
		Data:         []byte("go-ledger Genisis Block"),
		Transactions: []*Transaction{coinbase},
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	return b
}

// IsGenisis will return true if the block given
// is the genisis block.
func IsGenisis(b *Block) bool {
	return len(b.PrevHash) == 0 && len(b.Transactions) == 1
}

// CreateNext will create a new block using the data given and the
// hash of the current block.
func (b *Block) CreateNext(data []byte) *Block {
	block := &Block{
		Data:     data,
		PrevHash: b.Hash,
	}
	block.Nonce, block.Hash = ProofOfWork(block)
	return block
}

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
				Amount:     100,
				PubKeyHash: key.ExtractPubKeyHash(to),
			},
		},
	}
	tx.ID = tx.hash()
	return tx
}

// NewTransaction will create a new transaction.
func NewTransaction(chain Chain, to key.Receiver, from key.Sender, amount int64) (*Transaction, error) {
	var (
		inputs  []*TxInput
		outputs []*TxOutput
	)
	total, validOutputs := FindSpendableOuts(chain.Iter(), from, amount)
	if total < amount {
		return nil, ErrNotEnoughFunds
	}

	for txidStr, outIDs := range validOutputs {
		txID, err := hex.DecodeString(txidStr)
		if err != nil {
			return nil, err
		}
		for _, out := range outIDs {
			inputs = append(inputs, &TxInput{
				TxID:      txID,
				OutIndex:  int32(out),
				Signature: nil,
				PubKey:    from.PublicKey(),
			})
		}
	}
	outputs = append(outputs, &TxOutput{
		Amount:     amount,
		PubKeyHash: key.ExtractPubKeyHash(to.Address()),
	})
	if total > amount {
		// if there is money left over, create a new unspent output
		outputs = append(outputs, &TxOutput{
			Amount:     total - amount,
			PubKeyHash: from.PubKeyHash(),
		})
	}

	tx := &Transaction{Outputs: outputs, Inputs: inputs}
	tx.ID = tx.hash()

	prevtxs := make(map[string]*Transaction)
	for _, in := range inputs {
		prev := chain.Transaction(in.TxID)
		if prev == nil {
			continue
		}
		prevtxs[prev.StrID()] = prev
	}
	return tx, tx.Sign(from.PrivateKey(), prevtxs)
}

// UnspentTx will return the unspent transactions for a user address
func unspentTx(chain Iterator, pubkeyhash []byte) []*Transaction {
	// TODO: add a persistance layer that stores unspent transactions by public key
	var (
		spent   = make(map[string][]int)
		unspent []*Transaction
		block   *Block
	)

	for {
		block = chain.Next()
		for _, tx := range block.Transactions {
			txid := tx.StrID()
		NextOut:
			for outID, out := range tx.Outputs {
				// if the transaction has spent outputs
				// then we check that none of them are the
				// current output
				if spentTxIDs, ok := spent[txid]; ok {
					for _, spentTxID := range spentTxIDs {
						if spentTxID == outID {
							// go to the next output if the
							// current output is in the transaction's
							// list of spent outputs
							continue NextOut
						}
					}
				}
				// if it is not spent and is owned by the user
				// with the address then grab a copy of the transaction.
				if out.isLockedWith(pubkeyhash) {
					unspent = append(unspent, cloneTx(tx))
				}
			}

			// Inputs of a coinbase transactions do not reference an output.
			// https://en.bitcoin.it/wiki/Transaction#Generation
			if !tx.IsCoinbase() {
				for _, input := range tx.Inputs {
					inID := hex.EncodeToString(input.TxID)
					spent[inID] = append(spent[inID], int(input.OutIndex))
				}
			}
		}
		if IsGenisis(block) {
			break
		}
	}
	return unspent
}

// UnspentTxOutputs returns a list of outputs for one address that
// have not been spent
func UnspentTxOutputs(chain Iterator, address string) []*TxOutput {
	var unspentOut []*TxOutput
	pubkh := key.ExtractPubKeyHash(address)
	unspentTx := unspentTx(chain, pubkh)

	for _, tx := range unspentTx {
		for _, out := range tx.Outputs {
			if out.isLockedWith(pubkh) {
				unspentOut = append(unspentOut, out)
			}
		}
	}
	return unspentOut
}

// FindSpendableOuts will search the chain for spendable
// outputs for the address given some amount.
func FindSpendableOuts(
	chain Iterator,
	address key.Holder,
	amount int64,
) (
	total int64,
	unspent map[string][]int,
) {
	unspent = make(map[string][]int)
	pubkh := key.ExtractPubKeyHash(address.Address())
	unspentTxs := unspentTx(chain, pubkh)

	for _, tx := range unspentTxs {
		txid := tx.StrID()
		for outID, out := range tx.Outputs {
			if !out.isLockedWith(pubkh) {
				continue
			}
			if total < amount {
				total += out.Amount
				unspent[txid] = append(unspent[txid], outID)
				if total >= amount {
					return
				}
			}
		}
	}
	return
}

// Sign signs a tx
func (tx *Transaction) Sign(key *ecdsa.PrivateKey, prevtx map[string]*Transaction) error {
	if tx.IsCoinbase() {
		return nil
	}
	txcp := cloneTx(tx)
	for i, input := range txcp.Inputs {
		prev, ok := prevtx[hex.EncodeToString(input.TxID)]
		if ok && prev.ID == nil {
			return errors.New("transaction does not exist")
		}
		input.Signature = nil
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

// IsCoinbase will return true of the transaction
// is a coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && len(tx.Outputs) == 1 && tx.Inputs[0].OutIndex < 0
}

// StrID will return a hex encoded version of the transaction ID
func (tx *Transaction) StrID() string {
	return hex.EncodeToString(tx.ID)
}

func (tx *Transaction) hash() []byte {
	b, err := proto.Marshal(tx)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func newTxOutput(amount int64, to string) *TxOutput {
	return &TxOutput{Amount: amount, PubKeyHash: key.ExtractPubKeyHash(to)}
}

func (out *TxOutput) lock(address string) {
	out.PubKeyHash = key.ExtractPubKeyHash(address)
}

func (out *TxOutput) isLockedWith(pubkeyhash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubkeyhash) == 0
}

func (in *TxInput) useskey(pubkeyhash []byte) bool {
	lockHash := key.PubKey(in.PubKey).Hash()
	return bytes.Compare(lockHash, pubkeyhash) == 0
}

func cloneTx(t *Transaction) *Transaction {
	return proto.Clone(t).(*Transaction)
}

//go:generate protoc --go_out=. block.proto

package block

import (
	"errors"
	"fmt"

	"github.com/harrybrwn/go-ledger/key"
)

// ErrNotEnoughFunds is an error returned when a sender
// does not have enough money to make a transaction
var ErrNotEnoughFunds = errors.New("not enough funds")

// Chain is an interface that defines what a
// blockchain is.
type Chain interface {
	TxFinder
	Iter() Iterator
}

// Iterator is an interface that defines a block iterator
// api.
type Iterator interface {
	// returns the next block in the chain, value will
	// be nil if there are no more blocks. This should
	// return the genisis block as the last block
	Next() *Block
}

// TxFinder defines an interface for
// objects that can find transactions.
type TxFinder interface {
	// Transaction looks for a Transaction by ID
	// and returns nil if no transaction was found
	Transaction([]byte) *Transaction
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

// FindSpendableOuts will search the chain for spendable
// outputs for the address given some amount.
func FindSpendableOuts(
	chain Iterator,
	address key.Receiver,
	amount int64,
) (
	total int64,
	unspent map[string][]int,
) {
	pubkh := key.ExtractPubKeyHash(address.Address())
	stats := buildChainStats(chain)
	// return stats.balances[hex.EncodeToString(pubkh)], stats.spendable

	unspent = make(map[string][]int)
	// unspentTxs := unspentTx(chain, pubkh)
	for _, tx := range stats.unspent {
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

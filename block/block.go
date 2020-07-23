//go:generate protoc --go_out=. block.proto

package block

import (
	"crypto/sha256"
	"errors"
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
	return len(b.PrevHash) == 0 &&
		len(b.Transactions) == 1 &&
		b.Transactions[0].IsCoinbase()
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

func merkleroot(hashes [][]byte) []byte {
	n := len(hashes)
	if n == 1 {
		return hashes[0]
	}
	if n%2 != 0 {
		hashes = append(hashes, hashes[n-1])
		n++
	}
	var (
		hash = sha256.New()
		tree = make([][]byte, 0, n/2)
	)
	for i := 0; i < n; i += 2 {
		hash.Write(hashes[i])
		hash.Write(hashes[i+1])
		tree = append(tree, hash.Sum(nil))
		hash.Reset()
	}
	return merkleroot(tree)
}

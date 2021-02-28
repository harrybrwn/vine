//go:generate protoc -I../protobuf -I.. --go_out=paths=source_relative:. ../protobuf/block.proto

package block

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// MineReward is the reward you get from mining a block
const MineReward = 100

var (
	// ErrNotEnoughFunds is an error returned when a sender
	// does not have enough money to make a transaction
	ErrNotEnoughFunds = errors.New("not enough funds")

	// ErrBlockNotMined is the error returned when a block has not had
	// enough work done one it or it has not been mined (these are usually not
	// mutually exclusive).
	ErrBlockNotMined = errors.New("block has not been mined or done sufficient work")
)

// Chain is an interface that defines what a
// blockchain is.
type Chain interface {
	TxFinder
	Iter() Iterator
	Head() (*Block, error)
}

// Store defines an interface for objects that can store blocks
type Store interface {
	Chain
	Get([]byte) (*Block, error)
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
	Transaction(id []byte) *Transaction
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
	data := fmt.Sprintf("Genisis Block %v", time.Now())
	b := &Block{
		Data:         []byte(data),
		Transactions: []*Transaction{coinbase},
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	return b
}

// IsGenisis will return true if the block given
// is the genisis block.
func IsGenisis(b *Block) bool {
	return b != nil &&
		len(b.PrevHash) == 0 &&
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
	var (
		n    = len(hashes)
		hash = sha256.New()
		tree [][]byte
	)
	switch n {
	case 0:
		return nil
	case 1:
		return hashes[0]
	}

	if n%2 != 0 {
		hashes = append(hashes, hashes[n-1])
		n++
	}

	tree = make([][]byte, 0, n/2)
	for i := 0; i < n; i += 2 {
		hash.Write(hashes[i])
		hash.Write(hashes[i+1])
		tree = append(tree, hash.Sum(nil))
		hash.Reset()
	}
	return merkleroot(tree)
}

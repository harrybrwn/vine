package block

//go:generate protoc -I../protobuf -I.. --go_out=paths=source_relative:. ../protobuf/block.proto

import (
	"bytes"
	"crypto/sha256"
	"errors"
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
	Iter() Iterator
	Head() (*Block, error)
}

// Store defines an interface for objects that can store blocks
type Store interface {
	Chain
	Get([]byte) (*Block, error)
	Push(*Block) error
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
		Data:         nil,
		Transactions: txs,
		PrevHash:     prev,
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	return b
}

// Genisis creates the first block of the chain
func Genisis(coinbase *Transaction) *Block {
	data := "Genesis Block"
	b := &Block{
		Data:         []byte(data),
		Transactions: []*Transaction{coinbase},
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	return b
}

// DefaultGenesis block with pre-computed nonce and hash
func DefaultGenesis() *Block {
	// Pre computed hash with difficulty = 30
	// took 230.6s to compute
	b := &Block{
		Data: []byte("Genesis Block"),
		Hash: []byte{
			0x0, 0x0, 0x0, 0x3, 0x6c, 0xbc, 0xf1, 0x37, 0xc7, 0xfd, 0xc8,
			0x26, 0x16, 0x32, 0x8a, 0xc0, 0x33, 0xc0, 0x45, 0x3c, 0xb4,
			0xc2, 0x10, 0xbe, 0xb2, 0x7, 0x7, 0xd, 0xff, 0xf9, 0x6e, 0x66},
		Nonce:        297646011,
		PrevHash:     nil,
		Transactions: []*Transaction{},
	}
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

// IsDefaultGenesis will return true if the block given
// is the default genesis block
func IsDefaultGenesis(b *Block) bool {
	gen := DefaultGenesis()
	return b.Nonce == gen.Nonce &&
		bytes.Compare(b.Hash, gen.Hash) == 0 &&
		b.PrevHash == nil &&
		len(b.Transactions) == 0
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
		l      = len(hashes)
		hasher = sha256.New()
	)
	if l == 0 {
		return nil
	}
	for l > 1 {
		if l&1 == 1 {
			hashes = append(hashes, hashes[l-1])
			l++
		}
		j := 0
		for i := 0; i+1 < l; i += 2 {
			hasher.Write(hashes[i])
			hasher.Write(hashes[i+1])
			hashes[j] = hasher.Sum(nil)
			hasher.Reset()
			j++
		}
		l = l / 2
		hashes = hashes[:l]
	}
	return hashes[0]
}

// This is my attempt at translating the bitcoin merkleroot
// function from c++ to go... I'm not really sure why its
// still considered a merkle TREE??
func computeMerkleRoot(hashes [][]byte) []byte {
	var (
		l       = len(hashes)
		hasher  = sha256.New()
		mutated bool
	)
	for l > 1 {
		if mutated {
			for i := 0; i+1 < l; i += 2 {
				if bytes.Compare(hashes[i], hashes[i+1]) == 0 {
					mutated = true
				}
			}
		}
		if l&1 == 1 {
			hashes = append(hashes, hashes[l-1])
		}
		hasher.Write(hashes[0])
		hashes[0] = hasher.Sum(nil)
		hasher.Reset()
		l = l / 2
		hashes = hashes[:l]
	}
	return hashes[0]
}

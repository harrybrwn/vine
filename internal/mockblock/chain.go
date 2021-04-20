package mockblock

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/key"
)

// Chain is an in memory blockchain used for testing
type Chain struct {
	blocks []*block.Block
	txs    map[string]*block.Transaction
}

// NewChain returns a new block from the data and previous hash.
func NewChain(user key.Receiver) *Chain {
	c := &Chain{
		txs:    make(map[string]*block.Transaction),
		blocks: []*block.Block{},
	}
	b := block.Genisis(block.Coinbase(user))
	c.Append(b)
	return c
}

// Head gets the head block
func (c *Chain) Head() (*block.Block, error) {
	l := len(c.blocks)
	if l == 0 {
		return nil, errors.New("no blocks")
	}
	return c.blocks[l-1], nil
}

// Base returns the base of the chain
func (c *Chain) Base() (*block.Block, error) {
	return c.blocks[0], nil
}

// HeadHash returns the has of the head block
func (c *Chain) HeadHash() []byte {
	l := len(c.blocks)
	return c.blocks[l-1].Hash
}

// Get will get a block given it's hash
func (c *Chain) Get(h []byte) (*block.Block, error) {
	for _, blk := range c.blocks {
		if bytes.Compare(h, blk.Hash) == 0 {
			return blk, nil
		}
	}
	return nil, errors.New("could not find block")
}

// BlockByIndex indexes the underlying array of blocks
func (c *Chain) BlockByIndex(i int) *block.Block { return c.blocks[i] }

// Len returns the number of blocks
func (c *Chain) Len() int { return len(c.blocks) }

// Append will append a block to the end of the chain
func (c *Chain) Append(blk *block.Block) {
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
	}
	c.blocks = append(c.blocks, blk)
}

// Push will push a new block onto the chain
func (c *Chain) Push(blk *block.Block) error {
	c.Append(blk)
	return nil
}

// Transaction will get a transaction
func (c *Chain) Transaction(id []byte) *block.Transaction {
	if tx, ok := c.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Push a list of transactions onto the blockchain as a new block
func (c *Chain) push(desc []block.TxDesc) (err error) {
	// var e error
	// n := len(desc)
	// txs := make([]*block.Transaction, n)
	// stats := block.ChainStats(c.Iter())
	// for i := 0; i < n; i++ {
	// 	txs[i], e = block.NewTransaction(c, stats, &desc[i])
	// 	if e != nil && err == nil {
	// 		err = e
	// 	}
	// }
	// blk := block.New(txs, c.tophash())
	// c.append(blk)
	// return
	panic("not finished")
}

// Iter returns a block iterator
func (c *Chain) Iter() block.Iterator {
	return &blockIter{
		i:      len(c.blocks) - 1,
		blocks: c.blocks,
	}
}

type blockIter struct {
	i      int
	blocks []*block.Block
}

func (bi *blockIter) Next() *block.Block {
	if bi.i < 0 {
		return nil
	}
	b := bi.blocks[bi.i]
	bi.i--
	return b
}

func (c *Chain) tophash() []byte {
	return c.blocks[len(c.blocks)-1].Hash
}

package mockblock

import (
	"encoding/hex"

	"github.com/harrybrwn/blockchain/block"
	"github.com/harrybrwn/blockchain/key"
)

// Chain is a blockchain
type Chain struct {
	i      int
	blocks []*block.Block
	txs    map[string]*block.Transaction
}

// NewChain returns a new block from the data and previous hash.
func NewChain(user key.Holder) *Chain {
	c := &Chain{
		i:      1,
		txs:    make(map[string]*block.Transaction),
		blocks: []*block.Block{},
	}
	b := block.Genisis(block.Coinbase(user.Address()))
	c.append(b)
	return c
}

func (c *Chain) append(blk *block.Block) {
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
	}
	c.blocks = append(c.blocks, blk)
}

// Transaction will get a transaction
func (c *Chain) Transaction(id []byte) *block.Transaction {
	if tx, ok := c.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Iter returns a block iterator
func (c *Chain) Iter() block.Iterator {
	c.i = len(c.blocks) - 1
	return c
}

// Next gets the next block
func (c *Chain) Next() *block.Block {
	if c.i < 0 {
		return nil
	}
	b := c.blocks[c.i]
	c.i--
	return b
}

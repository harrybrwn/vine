package mockblock

import (
	"encoding/hex"

	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/key"
)

// Chain is an in memory blockchain used for testing
type Chain struct {
	i      int
	Blocks []*block.Block
	txs    map[string]*block.Transaction
}

// NewChain returns a new block from the data and previous hash.
func NewChain(user key.Receiver) *Chain {
	c := &Chain{
		i:      1,
		txs:    make(map[string]*block.Transaction),
		Blocks: []*block.Block{},
	}
	b := block.Genisis(block.Coinbase(user))
	c.append(b)
	return c
}

func (c *Chain) append(blk *block.Block) {
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
	}
	c.Blocks = append(c.Blocks, blk)
}

// Transaction will get a transaction
func (c *Chain) Transaction(id []byte) *block.Transaction {
	if tx, ok := c.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Push a list of transactions onto the blockchain as a new block
func (c *Chain) Push(desc []block.TxDesc) (err error) {
	var e error
	n := len(desc)
	txs := make([]*block.Transaction, n)
	stats := block.ChainStats(c.Iter())
	for i := 0; i < n; i++ {
		txs[i], e = block.NewTransaction(c, stats, &desc[i])
		if e != nil && err == nil {
			err = e
		}
	}
	blk := block.New(txs, c.tophash())
	c.append(blk)
	return
}

// Iter returns a block iterator
func (c *Chain) Iter() block.Iterator {
	c.i = len(c.Blocks) - 1
	return c
}

// Next gets the next block
func (c *Chain) Next() *block.Block {
	if c.i < 0 {
		return nil
	}
	b := c.Blocks[c.i]
	c.i--
	return b
}

func (c *Chain) tophash() []byte {
	return c.Blocks[len(c.Blocks)-1].Hash
}

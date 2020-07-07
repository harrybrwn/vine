package block

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/blockchain/key"
	"github.com/harrybrwn/blockchain/key/wallet"
)

func TestBlock(t *testing.T) {
	addr := wallet.New(wallet.Version1)
	c := newChain(addr)
	c.Push("1")
	if len(c.blocks) != 2 {
		t.Error("should have length 1")
	}
	c.Push("this is a test")
	for i := 0; i < 5; i++ {
		c.Push(fmt.Sprintf("test number %d", i))
	}
	for i := 0; i < len(c.blocks)-1; i++ {
		if cmp := bytes.Compare(c.blocks[i].Hash, c.blocks[i+1].PrevHash); cmp != 0 {
			t.Errorf(
				"invalid hash links between blocks %d (%x) and %d (%x)",
				i, c.blocks[i].Hash, i+1, c.blocks[i+1].PrevHash)
		}
	}
}

func TestPOW(t *testing.T) {
	addr := wallet.New(wallet.Version1).Address()
	block := New(
		[]*Transaction{Coinbase(addr)},
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	)
	nonce, hash := ProofOfWork(block)
	if nonce == 0 {
		t.Error("nonce should probably no be zero")
	}
	if len(hash) != 32 {
		t.Error("hash should be 32 bytes long")
	}
	if bytes.Compare(hash, hashBlock(difficulty, 0, block)) == 0 {
		t.Error("PoW hash ignored the nonce")
	}
	b := block
	b.Nonce, b.Hash = nonce, hash
	if !HasDoneWork(b) {
		t.Error("proof of work validation failed")
	}
}

func TestRPC(t *testing.T) {
	// this test is mainly a dummy test for gRPC
	b := New([]*Transaction{}, []byte{})
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Error(err)
	}

	block := &Block{}
	if err = proto.Unmarshal(raw, block); err != nil {
		t.Error(err)
	}
	if len(block.Hash) != 32 {
		t.Error("wrong hash length")
	}
	if bytes.Compare(b.Hash, block.Hash) != 0 {
		t.Error("decoded with wrong hash")
	}

	// tests below are for test coverage... sorry
	tx := Coinbase(t.Name())
	if len(tx.GetID()) == 0 || len(tx.ID) == 0 {
		t.Error("transaction has no ID")
	}
	if len(tx.GetInputs()) == 0 || len(tx.Inputs) == 0 {
		t.Error("tx has no inputs")
	}
	if len(tx.GetOutputs()) == 0 || len(tx.Outputs) == 0 {
		t.Error("tx has no outputs")
	}
	// now they should all be opposite
	tx = nil
	if len(tx.GetID()) != 0 {
		t.Error("transaction should have no ID")
	}
	if len(tx.GetInputs()) != 0 {
		t.Error("tx should have no inputs")
	}
	if len(tx.GetOutputs()) != 0 {
		t.Error("tx should have no outputs")
	}
}

func TestTx(t *testing.T) {
	harry := wallet.New(wallet.Version1)
	jim := wallet.New(wallet.Version1)

	c := newChain(harry) // harry gets the coinbase
	var bal int64 = 0
	bal, _ = FindSpendableOuts(c.Iter(), harry, 1)
	if bal <= 0 {
		t.Error("should have positive balance", bal)
	}

	err := c.addTx(jim, harry, 15)
	if err != nil {
		t.Error(err)
	}
	newbal, _ := FindSpendableOuts(c.Iter(), harry, 1)
	if newbal != (bal - 15) {
		t.Error("balance should be reduced by 15")
	}
	outs := UnspentTxOutputs(c.Iter(), harry.Address())
	bal = 0
	for _, o := range outs {
		bal += o.Amount
	}
	if newbal != bal {
		t.Errorf("should have gotten same balance: %d and %d", newbal, bal)
	}
	bal, _ = FindSpendableOuts(c.Iter(), jim, 1)
	if bal != 15 {
		t.Error("recipient should have gotten the money")
	}
	_, err = NewTransaction(c, harry, jim, 100)
	if err == nil {
		t.Error("expected an error")
	}
	if err != ErrNotEnoughFunds {
		t.Error("did not go get the expected error")
	}
}

// NewChain returns a new block from the data and previous hash.
func newChain(user key.Holder) *chain {
	c := &chain{
		i:      1,
		txs:    make(map[string]*Transaction),
		blocks: []*Block{},
	}
	b := Genisis(Coinbase(user.Address()))
	c.append(b)
	return c
}

// Chain implements the blockchain structure.
type chain struct {
	txs    map[string]*Transaction
	blocks []*Block
	i      int
}

func (chain *chain) addTx(to key.Receiver, from key.Sender, amount int64) error {
	tx, err := NewTransaction(chain, to, from, amount)
	if err != nil {
		return err
	}
	prev := chain.blocks[len(chain.blocks)-1].Hash
	chain.append(New([]*Transaction{tx}, prev))
	return nil
}

// Append will add a block to the ledger
func (chain *chain) append(blk *Block) {
	for _, tx := range blk.Transactions {
		chain.txs[tx.StrID()] = tx
	}
	chain.blocks = append(chain.blocks, blk)
}

func (chain *chain) Transaction(id []byte) *Transaction {
	if tx, ok := chain.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Push will add a block to the chain from just the data given.
func (chain *chain) Push(data string) {
	bytedata := []byte(data)
	prev := chain.blocks[len(chain.blocks)-1]
	chain.append(prev.CreateNext(bytedata))
}

func (chain *chain) Iter() Iterator {
	chain.i = len(chain.blocks) - 1
	return chain
}

func (chain *chain) Next() *Block {
	if chain.i < 0 {
		return nil
	}
	block := chain.blocks[chain.i]
	chain.i--
	return block
}

// TODO: find out how long it takes to
// solve the concensus algorithm, tweak to get 10 mins
func BenchAddBlock(b *testing.B) {
}

package block

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/key"
	"github.com/harrybrwn/go-ledger/key/wallet"
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

func TestBuildStats(t *testing.T) {
	eq, check := helpers(t)
	harry := wallet.New(wallet.Version1)
	jim := wallet.New(wallet.Version1)
	keyharry := hex.EncodeToString(harry.PubKeyHash())
	keyjim := hex.EncodeToString(jim.PubKeyHash())
	c := newChain(harry)

	check(c.addTx(jim, harry, 5))
	stats := buildChainStats(c.Iter())
	eq(stats.balances[keyharry], 100-5)
	eq(stats.balances[keyjim], 5)
	eq(stats.bal(jim), 5)
	eq(stats.bal(harry), 95)

	check(c.addTx(jim, harry, 90))
	stats = buildChainStats(c.Iter())
	eq(stats.balances[keyharry], 5)
	eq(stats.balances[keyjim], 95)
	eq(stats.bal(harry), 5)
	eq(stats.bal(jim), 95)

	check(c.addTx(harry, jim, 45))
	stats = buildChainStats(c.Iter())
	eq(stats.balances[keyharry], 50)
	eq(stats.balances[keyjim], 50)
	eq(stats.bal(harry), 50)
	eq(stats.bal(jim), 50)
}

func TestTransaction(t *testing.T) {
	eq, check := helpers(t)
	user1, user2, user3 := wallet.New(0x0), wallet.New(0x0), wallet.New(0x0)
	c := newChain(user1)
	s := buildChainStats(c.Iter())
	eq(s.bal(user1), 100)
	eq(s.bal(user2), 0)
	eq(s.bal(user3), 0)

	check(c.push([]txHead{{user1, user2, 10}}))
	s = buildChainStats(c.Iter())
	eq(s.bal(user1), 90)
	eq(s.bal(user2), 10)
	eq(s.bal(user3), 0)

	check(c.push([]txHead{
		{user1, user2, 5},
		{user2, user3, 10},
	}))
	s = buildChainStats(c.Iter())
	eq(s.bal(user1), 85)
	eq(s.bal(user2), 5)
	eq(s.bal(user3), 10)

	_, sp := s.spendableTxOutputs(user1, 0)
	fmt.Println(sp)

	// user4 := wallet.New(wallet.Version1)
	// check(c.push([]txHead{
	// 	{user1, user4, 85},
	// 	{user2, user4, 5},
	// 	{user3, user4, 10},
	// }))
	// s = buildChainStats(c.Iter())
	// eq(s.bal(user4), 99)
}

func TestTx(t *testing.T) {
}

func eq(t *testing.T, a, b interface{}) {
	t.Helper()
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if !av.Type().Comparable() || !bv.Type().Comparable() {
		t.Errorf("%T and %T are not comparable", a, b)
		return
	}
	if reflect.DeepEqual(a, b) {
		return
	}
	if av != bv {
		t.Errorf("%v and %v not equal", a, b)
		return
	}
}

func helpers(t *testing.T) (
	func(a, b int64),
	func(error),
) {
	t.Helper()
	eq := func(a, b int64) {
		t.Helper()
		if a != b {
			t.Errorf("%v and %v not equal", a, b)
		}
	}
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Error(e)
		}
	}
	return eq, check
}

func txMust(tx *Transaction, e error) *Transaction {
	if e != nil {
		panic(e)
	}
	return tx
}

// NewChain returns a new block from the data and previous hash.
func newChain(user key.Receiver) *chain {
	c := &chain{
		i:      1,
		txs:    make(map[string]*Transaction),
		blocks: []*Block{},
	}
	b := Genisis(Coinbase(user.Address()))
	c.append(b)
	// c.stats = buildChainStats(c.Iter())
	// c.stats = &chainStats{
	// 	spendable: make(map[string][]int),
	// 	balances:  make(map[string]int64),
	// 	spent:     make(map[string][]int),
	// 	unspent:   make([]*Transaction, 0),
	// 	utxo:      make([]*TxOutput, 0),
	// }
	return c
}

// Chain implements the blockchain structure.
type chain struct {
	txs    map[string]*Transaction
	blocks []*Block
	i      int
	// stats  *chainStats
}

func (c *chain) addTx(to key.Receiver, from key.Sender, amount int64) error {
	tx := &Transaction{}
	err := initTransaction(
		c,
		buildChainStats(c.Iter()),
		txHead{from: from, to: to, amount: amount},
		tx,
	)
	if err != nil {
		return err
	}
	c.append(New([]*Transaction{tx}, c.tophash()))
	return nil
}

func (c *chain) push(heads []txHead) (err error) {
	var e error
	n := len(heads)
	txs := make([]*Transaction, n)
	stats := buildChainStats(c.Iter())
	for i := 0; i < n; i++ {
		txs[i] = new(Transaction)
		e = initTransaction(c, stats, heads[i], txs[i])
		// txs[i], e = newTransaction(c, heads[i].to, heads[i].from, heads[i].amount)
		if e != nil && err == nil {
			err = e
		}
	}
	blk := New(txs, c.tophash())
	c.append(blk)
	return
}

// Append will add a block to the ledger
func (c *chain) append(blk *Block) {
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
	}
	c.blocks = append(c.blocks, blk)
}

// Bal gets a user's balance
func (c *chain) Bal(user key.Receiver) int64 {
	stats := buildChainStats(c.Iter())
	// return stats.balances[hex.EncodeToString(key.ExtractPubKeyHash(user.Address()))]
	return stats.bal(user)
}

func (c *chain) tophash() []byte {
	return c.blocks[len(c.blocks)-1].Hash
}

func (c *chain) Transaction(id []byte) *Transaction {
	if tx, ok := c.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Push will add a block to the chain from just the data given.
func (c *chain) Push(data string) {
	bytedata := []byte(data)
	prev := c.blocks[len(c.blocks)-1]
	c.append(prev.CreateNext(bytedata))
}

func (c *chain) Iter() Iterator {
	c.i = len(c.blocks) - 1
	return c
}

func (c *chain) Next() *Block {
	if c.i < 0 {
		return nil
	}
	block := c.blocks[c.i]
	c.i--
	return block
}

// TODO: find out how long it takes to
// solve the concensus algorithm, tweak to get 10 mins
func BenchAddBlock(b *testing.B) {
}

// this test is mainly a dummy test for gRPC stuff
func TestRPC(t *testing.T) {
	b := New([]*Transaction{{ID: []byte("testTX")}}, []byte{})
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
	b.Transactions[0].ID = []byte("changing the tx")

	// just making sure its a deep copy lol
	blockCp := proto.Clone(block).(*Block)
	if bytes.Compare(b.Hash, blockCp.Hash) != 0 {
		t.Error("decoded with wrong hash")
	}
	if string(blockCp.Transactions[0].ID) != "testTX" {
		t.Error("proto.Clone does not copy the inner data pointers")
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

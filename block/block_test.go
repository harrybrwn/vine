package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/key"
	"github.com/harrybrwn/go-ledger/key/wallet"
)

func init() {
	difficulty = 6
	// difficulty = 16
}

type testUser struct {
	*wallet.Wallet
	N int
}

func users(n int) []*testUser {
	u := []*testUser{}
	for i := 0; i < n; i++ {
		u = append(u, &testUser{N: i, Wallet: wallet.New()})
	}
	return u
}

type testChain struct {
	*chain
	users []*wallet.Wallet
}

func Test(t *testing.T) {
	t.Skip()
	user := users(5)
	c := newChain(user[0])
	c.pushblock(&Transaction{
		Inputs:  []*TxInput{{TxID: nil, OutIndex: -1, Signature: nil}},
		Outputs: []*TxOutput{{Amount: 50, PubKeyHash: user[4].PubKeyHash()}},
	})
	tx := []*Transaction{
		{
			Inputs: []*TxInput{{OutIndex: 0, PubKey: user[0].PublicKey()}},
			Outputs: []*TxOutput{
				{Amount: 5, PubKeyHash: user[1].PubKeyHash()},
				{Amount: 10, PubKeyHash: user[2].PubKeyHash()},
				{Amount: 25, PubKeyHash: user[4].PubKeyHash()},
			},
		},
	}
	for i := range tx {
		tx[i].ID = tx[i].hash()
	}
	raw, _ := json.MarshalIndent(tx, "", "    ")
	fmt.Printf("%s\n", raw)
}

func TestBlock(t *testing.T) {
	addr := wallet.New()
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
		b := c.blocks[i]
		next := c.blocks[i+1]
		if bytes.Compare(b.Hash, next.PrevHash) != 0 {
			t.Errorf(
				"invalid hash links between blocks %d (%x) and %d (%x)",
				i, c.blocks[i].Hash, i+1, c.blocks[i+1].PrevHash)
		}
	}
}

func TestPOW(t *testing.T) {
	addr := wallet.New()
	block := New(
		[]*Transaction{Coinbase(addr)},
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	)
	nonce, hash := ProofOfWork(block)
	if nonce == 0 {
		t.Errorf("nonce should probably no be zero: hash = %x", hash)
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
	harry := wallet.New()
	jim := wallet.New()
	keyharry := hex.EncodeToString(harry.PubKeyHash())
	keyjim := hex.EncodeToString(jim.PubKeyHash())
	c := newChain(harry)

	check(c.addTx(jim, harry, 5))
	stats := buildChainStats(c.Iter())
	eq(stats.balances[keyharry], coinbaseValue-5)
	eq(stats.balances[keyjim], 5)
	eq(stats.Bal(jim), 5)
	eq(stats.Bal(harry), coinbaseValue-5)

	check(c.addTx(jim, harry, 90))
	stats = buildChainStats(c.Iter())
	eq(stats.balances[keyharry], 5)
	eq(stats.balances[keyjim], 95)
	eq(stats.Bal(harry), 5)
	eq(stats.Bal(jim), 95)

	check(c.addTx(harry, jim, 45))
	stats = buildChainStats(c.Iter())
	eq(stats.balances[keyharry], 50)
	eq(stats.balances[keyjim], 50)
	eq(stats.Bal(harry), 50)
	eq(stats.Bal(jim), 50)
}

func TestMerkleTree(t *testing.T) {
	join := func(a, b []byte) []byte { return bytes.Join([][]byte{a, b}, nil) }
	h := func(hash []byte) []byte {
		res := sha256.Sum256(hash)
		return res[:]
	}
	sh := func(s string) []byte { return h([]byte(s)) }

	root := merkleroot([][]byte{})
	if len(root) != 0 {
		t.Error("no hashes should hash to zero length root")
	}
	pass1 := [][]byte{
		h(join(sh("one"), sh("two"))),
		h(join(sh("three"), h([]byte("four")))),
		h(join(h([]byte("five")), h([]byte("five")))),
	}
	pass2 := [][]byte{
		h(join(pass1[0], pass1[1])),
		h(join(pass1[2], pass1[2])),
	}
	expected := h(join(pass2[0], pass2[1]))

	res := merkleroot([][]byte{
		h([]byte("one")),
		h([]byte("two")),
		h([]byte("three")),
		h([]byte("four")),
		h([]byte("five")),
	})
	if bytes.Compare(res, expected) != 0 {
		t.Error("wrong merkle root computed")
	}

	root = merkleroot([][]byte{sh("a"), sh("b")})
	res = h(join(sh("a"), sh("b")))

	if bytes.Compare(root, res) != 0 {
		t.Error("wrong result")
	}

	root = merkleroot([][]byte{sh("test")})
	res = sh("test")
	if bytes.Compare(root, res) != 0 {
		t.Error("wrong result")
	}
}

func TestGetSpendableOutputs(t *testing.T) {
	user1, user2 := wallet.New(), wallet.New()
	if user2 == nil {
		t.Error("")
	}
	c := newChain(user1)
	it := c.Iter()
	for {
		block := it.Next()
		for _, tx := range block.Transactions {
			for _, o := range tx.Outputs {
				if bytes.Compare(o.PubKeyHash, user1.PubKeyHash()) == 0 {
					// fmt.Println(user1, o)
				}
			}
		}
		if IsGenisis(block) {
			break
		}
	}
}

func TestTransaction(t *testing.T) {
	eq, check := helpers(t)
	user1, user2, user3 := wallet.New(), wallet.New(), wallet.New()
	c := newChain(user1)
	s := buildChainStats(c.Iter())
	eq(s.Bal(user1), coinbaseValue)
	eq(s.Bal(user2), 0)
	eq(s.Bal(user3), 0)

	check(c.push([]TxDesc{{user1, user2, 10}}))
	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 90)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 0)

	// user1 pays 5  to user2
	// user2 pays 10 to user3
	check(c.push([]TxDesc{
		{user1, user2, 5},
		{user2, user3, 10},
	}))
	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 85)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 10)
	eq(s.Bal(user1)+s.Bal(user2)+s.Bal(user3), coinbaseValue)

	tx := &Transaction{}
	// user1 pays 25 to user2
	// user3 pays 5  to user2
	check(initTransaction(c, s, tx, TxDesc{user3, user2, 5}))
	check(initTransaction(c, s, tx, TxDesc{user1, user2, 25}))
	c.pushblock(tx)

	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 60)
	eq(s.Bal(user2), 35)
	eq(s.Bal(user3), 5)
	eq(s.Bal(user1)+s.Bal(user2)+s.Bal(user3), coinbaseValue)

	// Build a transaction from scratch so
	// we can add multiple inputs
	tx = &Transaction{}
	s = buildChainStats(c.Iter())
	receivers := make([]receiver, 0)
	for _, header := range []TxDesc{
		{From: user1, To: user2, Amount: 5},
		{From: user1, To: user3, Amount: 10},
	} {
		_, sp := s.spendableTxOutputs(header.From.PubKeyHash(), header.Amount)
		for txid, outs := range sp {
			txID, _ := hex.DecodeString(txid)
			for _, ix := range outs {
				tx.Inputs = append(tx.Inputs, &TxInput{TxID: txID, OutIndex: int32(ix), PubKey: header.From.PublicKey(), Signature: nil})
			}
		}
		receivers = append(receivers, receiver{to: header.To, amount: header.Amount})
	}
	outputs, err := newOutputs(user1, s.Bal(user1), receivers)
	if err != nil {
		t.Fatal(err)
	}
	tx.Outputs = append(tx.Outputs, outputs...)
	tx.ID = tx.hash()
	check(tx.Sign(user1.PrivateKey(), c))
	c.pushblock(tx)

	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 45)
	eq(s.Bal(user2), 40)
	eq(s.Bal(user3), 15)

	user4 := wallet.New()
	check(c.push([]TxDesc{
		{From: user1, To: user4, Amount: 45},
		{From: user2, To: user4, Amount: 40},
		{From: user3, To: user4, Amount: 15},
	}))
	s = buildChainStats(c.Iter())
	eq(s.Bal(user4), 100)
}

func TestTxSign(t *testing.T) {
	e := func(er error) {
		t.Helper()
		if er != nil {
			t.Fatal(er)
		}
	}
	// gen := mathrand.New(mathrand.NewSource(10))
	gen := rand.Reader

	k1, err := ecdsa.GenerateKey(elliptic.P256(), gen)
	e(err)
	k2, err := ecdsa.GenerateKey(elliptic.P256(), gen)
	e(err)
	if k1 == nil || k2 == nil {
		t.Error("keys are nil")
	}

	u1, u2 := wallet.New(), wallet.New()
	c := newChain(u1)
	e(c.addTx(u2, u1, 1))

	if u2 == nil {
		t.Error("nil wallet")
	}
	e(c.blocks[1].Transactions[0].VerifySig(c))

	// coin receiver's public key
	pub := &u2.PrivateKey().PublicKey
	pubkeyhash := bytes.Join([][]byte{
		pub.X.Bytes(), pub.Y.Bytes(),
	}, nil)
	pub = &u1.PrivateKey().PublicKey
	senderpub := bytes.Join([][]byte{
		pub.X.Bytes(), pub.Y.Bytes(),
	}, nil)
	tx := &Transaction{
		Inputs: []*TxInput{
			{
				TxID:      c.blocks[0].Transactions[0].hash(),
				OutIndex:  0,
				PubKey:    senderpub,
				Signature: nil,
			},
		},
		Outputs: []*TxOutput{
			{
				Amount:     1,
				PubKeyHash: pubkeyhash,
			},
		},
	}
	tx.ID = tx.hash()
	err = tx.Sign(u1.PrivateKey(), c)
	e(err)
	e(tx.VerifySig(c))
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
	func(a, b uint64),
	func(error),
) {
	t.Helper()
	eq := func(a, b uint64) {
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

// NewChain returns a new block from the data and previous hash.
func newChain(user key.Receiver) *chain {
	c := &chain{
		i:      1,
		txs:    make(map[string]*Transaction),
		blocks: []*Block{},
	}
	if user != nil {
		b := Genisis(Coinbase(user))
		c.append(b)
	}
	return c
}

// Chain implements the blockchain structure.
type chain struct {
	txs    map[string]*Transaction
	blocks []*Block
	i      int
}

func (c *chain) addTx(to key.Receiver, from key.Sender, amount uint64) error {
	tx, err := NewTransaction(
		c, buildChainStats(c.Iter()),
		&TxDesc{From: from, To: to, Amount: amount},
	)
	if err != nil {
		return err
	}
	c.append(New([]*Transaction{tx}, c.tophash()))
	return nil
}

type txReceiver struct {
	to     key.Receiver
	amount uint64
}

func (c *chain) push(heads []TxDesc) (err error) {
	var (
		e     error
		i     = 0
		recv  = make(map[string][]txReceiver)
		n     = len(heads)
		txs   = make([]*Transaction, 0, n)
		stats = buildChainStats(c.Iter())
	)
	for _, head := range heads {
		k := head.From.Address()
		recv[k] = append(recv[k], txReceiver{head.To, head.Amount})
	}

	txs = make([]*Transaction, n)
	for i = 0; i < n; i++ {
		txs[i], e = NewTransaction(c, stats, &heads[i])
		if e != nil && err == nil {
			err = e
		}
		c.txs[txs[i].StrID()] = txs[i]
	}
	blk := New(txs, c.tophash())
	c.append(blk)
	return
}

// Get will get a block given it's hash
func (c *chain) Get(h []byte) (*Block, error) {
	for _, blk := range c.blocks {
		if bytes.Compare(h, blk.Hash) == 0 {
			return blk, nil
		}
	}
	return nil, errors.New("could not find block")
}

func (c *chain) Head() (*Block, error) {
	return c.blocks[len(c.blocks)-1], nil
}

func (c *chain) pushblock(txs ...*Transaction) {
	c.append(New(txs, c.tophash()))
}

// Append will add a block to the ledger
func (c *chain) append(blk *Block) {
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
	}
	c.blocks = append(c.blocks, blk)
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
	b := prev.CreateNext(bytedata)
	c.append(b)
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
func BenchmarkPOW(b *testing.B) {
	blk := Genisis(Coinbase(address("test")))
	difficulty = 16
	for n := 0; n < b.N; n++ {
		// difficulty = hashDifficulty(n)
		ProofOfWork(blk)
	}
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
	tx := Coinbase(address(t.Name()))
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

type address string

func (a address) Address() string {
	return string(a)
}

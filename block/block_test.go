package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"os"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/harrybrwn/vine/internal/testutil"
	"github.com/harrybrwn/vine/key"
	"github.com/harrybrwn/vine/key/wallet"
)

// Toggle deterministic mode for some
// testing setup functions.
const deterministic = true

func init() {
	difficulty = 6
	// difficulty = 16
	// difficulty = 18

	if deterministic {
		rng = mathrand.New(mathrand.NewSource(13))
	}
	testutil.Deterministic = deterministic
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

func testWallet(t *testing.T, seed int64) *wallet.Wallet {
	return testutil.Wallet(t, seed)
}

func Test(t *testing.T) {
	t.Skip()

	difficulty = 30
	b := &Block{
		Data:         []byte("Genesis block"),
		Transactions: []*Transaction{},
	}
	b.Nonce, b.Hash = ProofOfWork(b)
	fmt.Printf("difficulty: %d\n", difficulty)
	fmt.Printf("nonce:      %d\n", b.Nonce)
	fmt.Printf("hash:       %#v\n", b.Hash)
	gen := DefaultGenesis()
	fmt.Println("reproducible:", bytes.Equal(b.Hash, gen.Hash) && b.Nonce == gen.Nonce)
	fmt.Println("is default genesis block:", IsDefaultGenesis(b))

	user := users(5)
	c := newChain(user[0])
	fmt.Printf("%x\n", c.blocks[0].Hash)
	c.append(New([]*Transaction{{
		Inputs:  []*TxInput{{TxID: nil, OutIndex: -1, Signature: nil}},
		Outputs: []*TxOutput{{Amount: 50, PubKeyHash: user[4].PubKeyHash()}},
	}}, c.tophash()))
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
	push := func(data string) {
		bytedata := []byte(data)
		prev := c.blocks[len(c.blocks)-1]
		b := prev.CreateNext(bytedata)
		c.append(b)
	}
	push("1")
	if len(c.blocks) != 2 {
		t.Error("should have length 1")
	}
	push("this is a test")
	for i := 0; i < 5; i++ {
		push(fmt.Sprintf("test number %d", i))
	}
	for i := 0; i < len(c.blocks)-1; i++ {
		b := c.blocks[i]
		next := c.blocks[i+1]
		if !bytes.Equal(b.Hash, next.PrevHash) {
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
		// TODO this error is triggered every once in a while, try to reproduce it
		t.Errorf(`nonce should probably no be zero: nonce = %d, hash = %x`, nonce, hash)
	}
	if len(hash) != 32 {
		t.Error("hash should be 32 bytes long")
	}
	if bytes.Equal(hash, hashBlock(difficulty, 0, block)) {
		t.Error("PoW hash ignored the nonce")
	}
	b := block
	b.Nonce, b.Hash = nonce, hash
	if !HasDoneWork(b) {
		t.Error("proof of work validation failed")
	}
}

func TestUTXOBalance(t *testing.T) {
	eq, check := helpers(t)
	bob := wallet.New()
	jim := wallet.New()
	c := newChain(bob)

	check(c.addTx(jim, bob, 5))
	stats := buildChainStats(c.Iter())
	eq(stats.Bal(jim), 5)
	eq(stats.Bal(bob), coinbaseValue-5)

	check(c.addTx(jim, bob, 90))
	stats = buildChainStats(c.Iter())
	eq(stats.Bal(bob), 5)
	eq(stats.Bal(jim), 95)

	check(c.addTx(bob, jim, 45))
	stats = buildChainStats(c.Iter())
	eq(stats.Bal(bob), 50)
	eq(stats.Bal(jim), 50)
	c.verifyAll(t)
}

func TestMerkleTree(t *testing.T) {
	join := func(a, b []byte) []byte { return bytes.Join([][]byte{a, b}, nil) }
	h := func(hash []byte) []byte {
		res := sha256.Sum256(hash)
		return res[:]
	}
	sh := func(s string) []byte { return h([]byte(s)) }

	root := merkleroot([][]byte{}, sha256.New())
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
	}, sha256.New())
	if !bytes.Equal(res, expected) {
		t.Error("wrong merkle root computed")
	}

	root = merkleroot([][]byte{sh("a"), sh("b")}, sha256.New())
	res = h(join(sh("a"), sh("b")))

	if !bytes.Equal(root, res) {
		t.Error("wrong result")
	}

	root = merkleroot([][]byte{sh("test")}, sha256.New())
	res = sh("test")
	if !bytes.Equal(root, res) {
		t.Error("wrong result")
	}
}

func TestBasicTransations(t *testing.T) {
	eq, check := helpers(t)
	user1, user2, user3 := testWallet(t, 1), testWallet(t, 2), testWallet(t, 3)
	c := newChain(user1)
	s := buildChainStats(c.Iter())
	eq(s.Bal(user1), coinbaseValue)
	eq(s.Bal(user2), 0)
	eq(s.Bal(user3), 0)

	check(c.pushWithStats(s, []TxDesc{{From: user1, To: user2, Amount: 10}}))
	eq(s.Bal(user1), 90)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 0)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user1, To: user3, Amount: 50}}))
	eq(s.Bal(user1), 40)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 50)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user2, To: user3, Amount: 5}}))
	eq(s.Bal(user1), 40)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 55)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user1, To: user3, Amount: 5}}))
	eq(s.Bal(user1), 35)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 60)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user3, To: user2, Amount: 7}}))
	eq(s.Bal(user1), 35)
	eq(s.Bal(user2), 5+7)
	if s.Bal(user3) != 60-7 {
		t.Errorf(`
            Chain stats did not find the correct
            balance when user spends from multiple UTXOs.
            want: %d, got %d`, 60-15, s.Bal(user3),
		)
	}

	err := c.pushWithStats(s, []TxDesc{{From: user3, To: user2, Amount: 100}})
	if err == nil {
		t.Error("should return error when attempting to overspend")
	}

	check(c.pushWithStats(s, []TxDesc{
		{From: user1, To: user2, Amount: 10},
		{From: user3, To: user2, Amount: 10},
	}))
	eq(s.Bal(user1), 25)
	eq(s.Bal(user2), 32)
	eq(s.Bal(user3), 43)
	for _, tx := range c.txlist {
		check(tx.VerifySig(c))
	}
}

func TestTransaction(t *testing.T) {
	eq, check := helpers(t)
	user1, user2, user3 := testWallet(t, 1), testWallet(t, 2), testWallet(t, 3)
	c := newChain(user1)
	s := buildChainStats(c.Iter())
	eq(s.Bal(user1), coinbaseValue)
	eq(s.Bal(user2), 0)
	eq(s.Bal(user3), 0)

	check(c.pushWithStats(s, []TxDesc{{user1, user2, 10}}))
	c.verifyPrevTxSig(t)
	eq(s.Bal(user1), 90)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 0)

	// return

	check(c.pushWithStats(s, []TxDesc{
		{From: user1, To: user2, Amount: 5},
		{From: user2, To: user3, Amount: 10},
	}))
	c.verifyPrevTxSig(t)
	if !c.verifyAll(t) {
		dbg := newChainDebugger(c, []key.Sender{user1, user2, user3})
		dbg.printChain(c.Iter())
		return
	}
	// logging = false
	eq(s.Bal(user1), 85)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 10)
	eq(s.Bal(user1)+s.Bal(user2)+s.Bal(user3), coinbaseValue)

	check(c.pushWithStats(s, []TxDesc{
		{From: user3, To: user2, Amount: 5},
		{From: user1, To: user2, Amount: 25},
	}))
	c.verifyPrevTxSig(t)
	eq(s.Bal(user1), 60)
	eq(s.Bal(user2), 35)
	eq(s.Bal(user3), 5)
	eq(s.Bal(user1)+s.Bal(user2)+s.Bal(user3), coinbaseValue)

	c.pushWithStats(s, []TxDesc{
		{From: user1, To: user2, Amount: 5},
		{From: user1, To: user3, Amount: 10},
	})
	c.verifyPrevTxSig(t)
	eq(s.Bal(user1), 45)
	eq(s.Bal(user2), 40)
	eq(s.Bal(user3), 15)

	user4 := testWallet(t, 4)
	check(c.pushWithStats(s, []TxDesc{
		{From: user1, To: user4, Amount: 45},
		{From: user2, To: user4, Amount: 40},
		{From: user3, To: user4, Amount: 15},
	}))
	c.verifyPrevTxSig(t)

	eq(s.Bal(user4), 100)
	for i, u := range []*wallet.Wallet{
		user1,
		user2,
		user3,
	} {
		if b := s.Bal(u); b != 0 {
			t.Errorf(`Balance should be zero for user%d, got %v`, i+1, b)
		}
	}
	if !c.verifyAll(t) {
		dbg := newChainDebugger(c, []key.Sender{user1, user2, user3, user4})
		dbg.printChain(c.Iter())
	}
}

func TestTxSign(t *testing.T) {
	t.Skip()
	e := func(er error) {
		t.Helper()
		if er != nil {
			t.Fatal(er)
		}
	}
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
	e(tx.Sign(u1.PrivateKey(), c))
	e(tx.VerifySig(c))
}

func TestChainStats(t *testing.T) {
	eq, check := helpers(t)
	user1, user2, user3 := testWallet(t, 1), testWallet(t, 2), testWallet(t, 3)

	c := newChain(user1)
	s := buildChainStats(c.Iter())
	eq(s.Bal(user1), coinbaseValue)
	eq(s.Bal(user2), 0)
	eq(s.Bal(user3), 0)
	check(c.prevtx[0].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{user1, user2, 10}}))
	eq(s.Bal(user1), 90)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 0)
	c.verifyPrevTxSig(t)

	check(c.pushWithStats(s, []TxDesc{{From: user1, To: user3, Amount: 50}}))
	eq(s.Bal(user1), 40)
	eq(s.Bal(user2), 10)
	eq(s.Bal(user3), 50)
	eq(uint64(len(s.Unspent(user3))), 1)
	check(c.prevtx[0].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user2, To: user3, Amount: 5}}))
	eq(s.Bal(user1), 40)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 55)
	eq(uint64(len(s.Unspent(user3))), 2)
	check(c.prevtx[0].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user1, To: user3, Amount: 5}}))
	eq(s.Bal(user1), 35)
	eq(s.Bal(user2), 5)
	eq(s.Bal(user3), 60)
	eq(uint64(len(s.Unspent(user3))), 3)
	check(c.prevtx[0].VerifySig(c))

	check(c.pushWithStats(s, []TxDesc{{From: user3, To: user2, Amount: 7}}))
	eq(s.Bal(user1), 35)
	eq(s.Bal(user2), 12)
	eq(s.Bal(user3), 53)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	desc := TxDesc{From: user3, To: user2, Amount: 60}
	err := c.push([]TxDesc{desc})
	if err == nil {
		t.Error("expected error when trying to overspend")
	}
	eq(s.Bal(user1), 35)
	eq(s.Bal(user2), 12)
	eq(s.Bal(user3), 53)
	check(c.txlist[len(c.txlist)-1].VerifySig(c))

	tx, err := createTx(buildChainStats(c.Iter()), user3, []TxDesc{
		{To: user2, Amount: 3},
		{To: user1, Amount: 50},
	})
	check(err)
	check(tx.Sign(user3.PrivateKey(), c))
	c.append(New([]*Transaction{tx}, c.tophash()))
	c.verifyAll(t)

	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 35+50)
	eq(s.Bal(user2), 15)
	eq(s.Bal(user3), 0)

	tx = new(Transaction)
	check(tx.Append(s, TxDesc{From: user1, To: user3, Amount: 1}))
	check(tx.Append(s, TxDesc{From: user2, To: user3, Amount: 2}))
	tx.ID = tx.hash()
	check(tx.Sign(user1.PrivateKey(), c))
	c.append(New([]*Transaction{tx}, c.tophash()))
	check(s.Update(tx))

	// dbg := newChainDebugger(c, []key.Sender{user1, user2, user3})
	// dbg.printChain(c.Iter())
	// check(tx.VerifySig(c))
	// c.verifyAll(t)

	s = buildChainStats(c.Iter())
	eq(s.Bal(user1), 84)
	eq(s.Bal(user2), 13)
	eq(s.Bal(user3), 3)
}

func TestLarge(t *testing.T) {
	eq, check := helpers(t)
	eq(1, 1)
	check(nil)
	users := []key.Sender{
		testWallet(t, 0), testWallet(t, 1),
		testWallet(t, 2), testWallet(t, 3),
		testWallet(t, 4), testWallet(t, 5),
	}
	c := newChain(users[0])
	s := buildChainStats(c.Iter())
	eq(s.Bal(users[0]), 100)

	dbg := newChainDebugger(c, users)
	if dbg == nil {
		t.Fail()
	}
	descs := make([]TxDesc, 0)
	for i := 1; i < len(users); i++ {
		descs = append(descs, TxDesc{
			Amount: 5,
			From:   users[0],
			To:     users[i],
		})
	}
	check(c.pushWithStats(s, descs))
	eq(s.Bal(users[0]), 100-(5*5))
	eq(s.Bal(users[1]), 5)
	eq(s.Bal(users[2]), 5)
	eq(s.Bal(users[3]), 5)
	eq(s.Bal(users[4]), 5)
	eq(s.Bal(users[5]), 5)

	check(c.pushWithStats(s, []TxDesc{
		{Amount: 15, From: users[0], To: users[1]},
		{Amount: 18, From: users[0], To: users[2]},
		{Amount: 3, From: users[3], To: users[4]},
		{Amount: 1, From: users[4], To: users[2]},
		{Amount: 4, From: users[1], To: users[0]},
	}))
	eq(s.Bal(users[5]), 5)
	eq(s.Bal(users[4]), 7)
	eq(s.Bal(users[3]), 2)
	eq(s.Bal(users[2]), 5+18+1)
	eq(s.Bal(users[1]), 16)
	eq(s.Bal(users[0]), 75-15-18+4)
	eq(s.Bal(users[0]), 46)

	check(c.pushWithStats(s, []TxDesc{
		{Amount: 8, From: users[2], To: users[3]},
		{Amount: 8, From: users[2], To: users[4]},
		{Amount: 8, From: users[2], To: users[5]},
		{Amount: 0, From: users[1], To: users[0]},
		{Amount: 0, From: users[0], To: users[1]},
	}))
	eq(s.Bal(users[2]), 0)
	eq(s.Bal(users[3]), 8+2)
	eq(s.Bal(users[4]), 8+7)
	eq(s.Bal(users[5]), 8+5)
	eq(s.Bal(users[1]), 16)
	eq(s.Bal(users[0]), 46)

	check(c.pushWithStats(s, []TxDesc{
		{Amount: s.Bal(users[4]), From: users[4], To: users[5]},
	}))
	eq(s.Bal(users[5]), 28)
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
	func(error) bool,
) {
	t.Helper()
	eq := func(a, b uint64) {
		t.Helper()
		if a != b {
			t.Errorf("%v and %v not equal", a, b)
		}
	}
	check := func(e error) bool {
		t.Helper()
		if e != nil {
			t.Error(e)
			return false
		}
		return true
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

	txlist []*Transaction
	prevtx []*Transaction
}

func buildChainStats(it Iterator) *chainStats {
	var s = &chainStats{
		spent:    make(map[string][]int),
		balances: make(map[string]uint64),
		utxo:     make(map[string][]*UTXO),
	}
	s.ReIndex(it)
	return s
}

func (c *chain) addTx(to key.Receiver, from key.Sender, amount uint64) error {
	// tx, err := NewTransaction(
	// 	c, buildChainStats(c.Iter()),
	// 	TxDesc{From: from, To: to, Amount: amount},
	// )
	stats := buildChainStats(c.Iter())
	tx, err := createTx(stats, from, []TxDesc{{From: from, To: to, Amount: amount}})
	if err != nil {
		return err
	}
	err = stats.Update(tx)
	if err != nil {
		return err
	}
	if err = tx.Sign(from.PrivateKey(), c); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	c.append(New([]*Transaction{tx}, c.tophash()))
	return nil
}

func (c *chain) pushWithStats(stats *chainStats, heads []TxDesc) (err error) {
	type txReceiver struct {
		from key.Sender
		recv []TxDesc
	}
	const keylen = 121
	var (
		n    = len(heads)
		txs  = make([]*Transaction, 0, n)
		recv = make(map[[keylen]byte]*txReceiver)
	)
	if n == 0 {
		return errors.New("no transaction can be created with no TxDesc")
	}

	// Create a map of senders to receivers
	// such that there is only one sender per
	// new transaction.
	for _, head := range heads {
		k := privKeyBytes(head.From)
		if _, ok := recv[k]; ok {
			priv := privKeyBytes(recv[k].from)
			if !bytes.Equal(priv[:], k[:]) {
				panic("keys don't match")
			}
			recv[k].recv = append(recv[k].recv, TxDesc{
				To:     head.To,
				Amount: head.Amount,
			})
		} else {
			recv[k] = &txReceiver{
				from: head.From,
				recv: []TxDesc{{To: head.To, Amount: head.Amount}},
			}
		}
	}

	// Create one new transaction for every sender
	for _, descs := range recv {
		tx, err := createTx(stats, descs.from, descs.recv)
		if err != nil {
			return err
		}
		err = tx.Sign(descs.from.PrivateKey(), c)
		if err != nil {
			return err
		}
		if err = stats.Update(tx); err != nil {
			return err
		}
		txs = append(txs, tx)
	}

	blk := New(txs, c.tophash())
	c.append(blk)
	return
}

func (c *chain) verifyAll(t *testing.T) bool {
	t.Helper()
	var (
		err     error
		success = true
		txno    = 0
		it      = c.Iter()
		j       = 0
	)
	for {
		blk := it.Next()
		if IsGenisis(blk) {
			break
		}
		for i, tx := range blk.Transactions {
			if tx.IsCoinbase() {
				continue
			}
			if err = tx.VerifySig(c); err != nil {
				t.Errorf("(%d) [block %d, tx %d]: TxID: %s, error: %v", txno, j, i, tx.StrID(), err)
				success = false
			}
			txno++
		}
		j++
	}
	return success
}

func (c *chain) push(heads []TxDesc) (err error) {
	return c.pushWithStats(buildChainStats(c.Iter()), heads)
}

// Get will get a block given it's hash
func (c *chain) Get(h []byte) (*Block, error) {
	for _, blk := range c.blocks {
		if bytes.Equal(h, blk.Hash) {
			return blk, nil
		}
	}
	return nil, errors.New("could not find block")
}

func (c *chain) Head() (*Block, error) {
	return c.blocks[len(c.blocks)-1], nil
}

func (c *chain) Append(blk *Block) error {
	c.append(blk)
	return nil
}

// Append will add a block to the ledger
func (c *chain) append(blk *Block) {
	c.prevtx = make([]*Transaction, 0)
	for _, tx := range blk.Transactions {
		c.txs[tx.StrID()] = tx
		c.txlist = append(c.txlist, tx)
		c.prevtx = append(c.prevtx, tx)
	}
	c.blocks = append(c.blocks, blk)
}

func (c *chain) tophash() []byte {
	return c.blocks[len(c.blocks)-1].Hash
}

func (c *chain) verifyPrevTxSig(t *testing.T) {
	t.Helper()
	tx := c.txlist[len(c.txlist)-1]
	err := tx.VerifySig(c)
	switch err {
	case nil:
		return
	case ErrInvalidSignature:
		t.Errorf("got an invalid signature in tx %s", tx.StrID())
		raw, _ := json.Marshal(map[string]interface{}{"txid": tx.ID})
		t.Errorf("%s\n", raw)
		panic(err)
	default:
		t.Error(err)
	}
}

func (c *chain) Transaction(id []byte) *Transaction {
	if tx, ok := c.txs[hex.EncodeToString(id)]; ok {
		return tx
	}
	return nil
}

// Push will add a block to the chain from just the data given.
func (c *chain) Push(*Block) error {
	panic("Push not implemented")
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

var (
	_ Iterator = (*chain)(nil)
	_ Chain    = (*chain)(nil)
	_ Store    = (*chain)(nil)
	_ TxFinder = (*chain)(nil)
	_ UTXOSet  = (*chainStats)(nil)
)

type userinfo struct {
	user key.Sender
	name string
}

// Map of public key hashes to user info
type chaindebugger map[string]userinfo

func newChainDebugger(c *chain, users []key.Sender) chaindebugger {
	dbg := make(chaindebugger)
	for i, u := range users {
		key := u.PubKeyHash()
		dbg[hex.EncodeToString(key)] = userinfo{
			user: u,
			name: fmt.Sprintf("user(%d)", i),
		}
	}
	return dbg
}

func (dbg chaindebugger) printChain(it Iterator) {
	var w io.Writer = os.Stdout
	for {
		blk := it.Next()
		if blk == nil {
			break
		}

		fmt.Fprintf(w, "Block(%.10x...)\n", blk.Hash)
		for _, tx := range blk.Transactions {
			fmt.Fprintf(w, "  TX(%.10x)\n", tx.ID)
			fmt.Fprintf(w, "    lock: %v,\n", ptypes.TimestampString(tx.Lock))
			for _, in := range tx.Inputs {
				fmt.Fprintf(w, "    In(")
				var hash []byte = nil
				if in.PubKey != nil {
					hash = key.PubKey(in.PubKey).Hash()
				}
				fmt.Fprintf(w, "user:  %s, ", dbg.name(hash))
				fmt.Fprintf(w, "index: %-d, ", in.OutIndex)
				fmt.Fprintf(w, "tx: %.10x, ", in.TxID)
				fmt.Fprintf(w, "pubhash: %.10x, ", key.PubKey(in.PubKey).Hash())
				fmt.Fprintf(w, "pubkey: %.10x, ", in.PubKey)
				fmt.Fprintf(w, "sig: %.10x, ", in.Signature)
				fmt.Fprintf(w, "\b\b)\n")
			}

			for i, out := range tx.Outputs {
				fmt.Fprintf(w, "    Out(")
				fmt.Fprintf(w, "user: %s, ", dbg.name(out.GetPubKeyHash()))
				fmt.Fprintf(w, "index: %-d, ", i)
				fmt.Fprintf(w, "amount: %d, ", out.Amount)
				fmt.Fprintf(w, "pubhash: %.10x, ", out.PubKeyHash)
				fmt.Fprintf(w, "\b\b)\n")
			}
		}
		fmt.Fprintf(w, "\n")
		if IsGenisis(blk) {
			break
		}
	}
	fmt.Fprintf(w, "End Chain")
}

func (dbg chaindebugger) name(pubkeyhash []byte) string {
	if pubkeyhash == nil {
		return "<none>"
	}
	return dbg[hex.EncodeToString(pubkeyhash)].name
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

// this test is mainly a dummy test for protobuf stuff
func TestProto(t *testing.T) {
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
	if !bytes.Equal(b.Hash, block.Hash) {
		t.Error("decoded with wrong hash")
	}
	b.Transactions[0].ID = []byte("changing the tx")

	// just making sure its a deep copy lol
	blockCp := proto.Clone(block).(*Block)
	if !bytes.Equal(b.Hash, blockCp.Hash) {
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

func (a address) Address() string    { return string(a) }
func (a address) PubKeyHash() []byte { return key.ExtractPubKeyHash(string(a)) }

func privKeyBytes(k key.Sender) [121]byte {
	var key [121]byte
	b, err := x509.MarshalECPrivateKey(k.PrivateKey())
	if err != nil {
		panic(err)
	}
	copy(key[:], b)
	return key

	// var (
	// 	key  [64]byte
	// 	priv = k.PrivateKey()
	// )

	// copy(key[:32], priv.X.Bytes())
	// copy(key[32:], priv.Y.Bytes())
	// return key
}

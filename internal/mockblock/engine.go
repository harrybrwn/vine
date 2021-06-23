package mockblock

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/key"
	"github.com/harrybrwn/vine/key/wallet"
	"github.com/pkg/errors"
)

// Engine is a type that is meant to facilitate
// randomized transactions for the purpose of testing
type Engine struct {
	Chain  block.Chain
	UTXO   block.UTXOSet
	finder block.TxFinder

	users     map[string]key.Sender
	addresses []string

	seed   int64
	source mathrand.Source
	rng    io.Reader

	// Number of steps until a new
	// user is randomly generated
	// and added to the system
	probOfNewUser int

	t *testing.T
}

func NewEngine(t *testing.T, chain block.Chain, users []key.Sender) *Engine {
	u := make(map[string]key.Sender)
	addrs := make([]string, 0, len(users))
	for _, user := range users {
		a := user.Address()
		u[a] = user
		addrs = append(addrs, a)
	}
	return &Engine{
		Chain:         chain,
		UTXO:          block.BuildUTXOSet(chain.Iter()),
		finder:        bruteForceTxFinder(chain),
		users:         u,
		addresses:     addrs,
		rng:           rand.Reader,
		source:        mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
		probOfNewUser: 75000,
		t:             t,
	}
}

func (e *Engine) SetSeed(seed int64) {
	e.seed = seed
	e.source = mathrand.NewSource(seed)
	e.rng = mathrand.New(e.source)
}

// Step will run through n steps of the transaction
// generation engine.
func (e *Engine) Step(n int) error {
	e.t.Helper()
	var err error
	for i := 0; i < n; i++ {
		if err = e.next(); err != nil {
			e.t.Errorf("Engine Error: %+v", err)
			return errors.WithStack(err)
		}
	}
	return nil
}

func (e *Engine) next() error {
	var (
		err  error
		recv []key.Sender
		txs  = make([]*block.Transaction, 0)
		n    = max(1, e.rand(len(e.addresses)-1))
	)

	builder := TransactionBuilder{
		txs: make(map[[121]byte]*builderMetaData),
		set: e.UTXO,
	}
	for i := 0; i < n; i++ {
		user := e.randomSender()
		bal := e.UTXO.Bal(user)
		receivers, err := e.randomUsers()
		if err != nil {
			return err
		}
		for _, u := range receivers {
			if bytes.Compare(u.PubKeyHash(), user.PubKeyHash()) == 0 {
				continue
			}
			amount := uint64(max(1, e.rand(int(bal))))
			bal -= amount
			if bal < 0 {
				break
			}
			err = builder.Append(block.TxDesc{
				From:   user,
				To:     u,
				Amount: uint64(max(1, e.rand(int(bal)))),
			})
			if err != nil {
				return err
			}
		}
	}
	trans, err := builder.BuildTransactions(e.finder)
	if err != nil {
		return err
	}
	// for _, t := range trans {
	// 	t.tx.Finalize()
	// 	err = t.tx.Sign(t.sender.PrivateKey(), e.finder)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	err = e.UTXO.Update(t.tx)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	txs = append(txs, t.tx)
	// }
	txs = trans
	head, err := e.Chain.Head()
	if err != nil {
		return errors.WithStack(err)
	}
	blk := block.New(txs, head.Hash)
	if chain, ok := e.Chain.(*Chain); ok {
		return errors.WithStack(chain.Push(blk))
	}
	if chain, ok := e.Chain.(interface{ Append(*block.Block) error }); ok {
		return errors.WithStack(chain.Append(blk))
	}
	return errors.New("could not append to blockchain")

	fmt.Println("builder output len:", len(trans))

	for i := 0; i < n && len(txs) < 1; i++ {
		user := e.randomSender()
		bal := e.UTXO.Bal(user)
		recv, err = e.randomUsers()
		if err != nil {
			return errors.WithStack(err)
		}
		tx := block.NewTransaction()
		for _, u := range recv {
			if bytes.Compare(u.PubKeyHash(), user.PubKeyHash()) == 0 {
				continue
			}
			// Retry:
			amount := uint64(e.rand(int(bal)))
			if amount == 0 {
				continue
			}
			bal -= amount
			if bal < 0 {
				panic("what?")
				break
			}
			fmt.Println("bal:", bal, ", amount:", amount)
			err = tx.Append(e.UTXO, block.TxDesc{
				From: user, To: u,
				Amount: uint64(amount)},
			)
			if err != nil {
				// goto Retry
				panic(err)
				break
			}
		}
		tx.Finalize()
		err = e.UTXO.Update(tx)
		if err != nil {
			return err
			continue
			// break
			// return errors.WithStack(err)
		}
		err = tx.Sign(user.PrivateKey(), e.finder)
		if err != nil {
			// continue
			return err
			break
			// return errors.WithStack(err)
		}
		txs = append(txs, tx)
	}

	// head, err := e.Chain.Head()
	// if err != nil {
	// 	return errors.WithStack(err)
	// }
	// fmt.Println("txs:", len(txs))
	// blk := block.New(txs, head.Hash)
	// if chain, ok := e.Chain.(*Chain); ok {
	// 	return errors.WithStack(chain.Push(blk))
	// }
	// if chain, ok := e.Chain.(interface{ Append(*block.Block) error }); ok {
	// 	return errors.WithStack(chain.Append(blk))
	// }
	return errors.New("could not append to blockchain")
}

func (e *Engine) randomUser() (key.Sender, error) {
	if e.rand(e.probOfNewUser) == 0 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), e.rng)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		user := wallet.FromKey(key)
		e.addUser(user)
		return user, nil
	}
	addr := e.addresses[e.rand(len(e.addresses))]
	return e.users[addr], nil
}

func (e *Engine) randomUsers() ([]key.Sender, error) {
	var (
		err   error
		n     = max(1, e.rand(len(e.addresses)-1))
		users = make([]key.Sender, n)
	)
	for i := 0; i < n; i++ {
		users[i], err = e.randomUser()
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func (e *Engine) randomSender() key.Sender {
	addr := e.addresses[e.rand(len(e.addresses))]
	user := e.users[addr]
	for e.UTXO.Bal(user) <= 0 {
		addr = e.addresses[e.rand(len(e.addresses))]
		user = e.users[addr]
	}
	return user
}

func (e *Engine) rand(n int) int {
	if n&(n-1) == 0 {
		return int((e.source.Int63())>>32) & (n - 1)
	}
	max := int((1 << 31) - 1 - (1<<31)%uint32(n))
	v := int(e.source.Int63() >> 32)
	for v > max {
		v = int(e.source.Int63() >> 32)
	}
	return int(e.source.Int63()) % n
}

func (e *Engine) addUser(u key.Sender) {
	a := u.Address()
	_, ok := e.users[a]
	if ok {
		return
	}
	e.users[a] = u
	e.addresses = append(e.addresses, a)
}

type txFinderFunc func([]byte) *block.Transaction

func (f txFinderFunc) Transaction(hash []byte) *block.Transaction {
	return f(hash)
}

func bruteForceTxFinder(chain block.Chain) block.TxFinder {
	return txFinderFunc(func(h []byte) *block.Transaction {
		it := chain.Iter()
		for {
			blk := it.Next()
			for _, tx := range blk.Transactions {
				if bytes.Compare(h, tx.ID) == 0 {
					return tx
				}
			}
			if block.IsGenisis(blk) {
				return nil
			}
		}
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type TransactionBuilder struct {
	// map of x509 encoded private key to tx data
	txs map[[121]byte]*builderMetaData
	set block.UTXOSet
}

type builderMetaData struct {
	from key.Sender
	recv []block.TxDesc
}

func (txb *TransactionBuilder) Append(d block.TxDesc) error {
	var key [121]byte
	b, err := x509.MarshalECPrivateKey(d.From.PrivateKey())
	if err != nil {
		return err
	}
	copy(key[:], b)

	senderData, ok := txb.txs[key]
	if ok {
		senderData.recv = append(txb.txs[key].recv, d)
	} else {
		txb.txs[key] = &builderMetaData{
			from: d.From,
			recv: []block.TxDesc{d},
		}
	}
	return nil
}

type txHolder struct {
	tx     *block.Transaction
	sender key.Sender
}

func (txb *TransactionBuilder) BuildTransactions(f block.TxFinder) ([]*block.Transaction, error) {
	var (
		// err error
		txs = make([]*block.Transaction, 0)
		// txs = make([]txHolder, 0)
	)
	for _, meta := range txb.txs {
		tx := block.NewTransaction()
		tx, err := block.CreateTx(txb.set, meta.from, meta.recv)
		if err != nil {
			return nil, err
		}
		err = tx.Sign(meta.from.PrivateKey(), f)
		if err != nil {
			return nil, err
		}

		err = txb.set.Update(tx)
		if err != nil {
			return nil, err
		}
		// for _, desc := range meta.recv {
		// 	if err = tx.Append(txb.set, desc); err != nil {
		// 		return nil, err
		// 	}
		// }
		// txs = append(txs, txHolder{tx: tx, sender: meta.from})
		txs = append(txs, tx)
	}
	return txs, nil
}

func (txb *TransactionBuilder) Reset() {
	txb.txs = make(map[[121]byte]*builderMetaData)
}

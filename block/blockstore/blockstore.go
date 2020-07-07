package blockstore

import (
	"bytes"

	badger "github.com/dgraph-io/badger/v2"
	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/blockchain/block"
	"github.com/pkg/errors"
)

var headKey = []byte("head")

// New creates a new BlockStore
func New(address string, dir string) (*BlockStore, error) {
	opts := badger.DefaultOptions(dir)
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	store := &BlockStore{db: db}

	err = db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(headKey)
		// if the key "head" is not found in the database then
		// create the genisis block, otherwise we store the
		// hash pointed to by the "head" key.
		if err == badger.ErrKeyNotFound {
			genisis := block.Genisis(block.Coinbase(address))

			rawBlock, err := proto.Marshal(genisis)
			if err != nil {
				return errors.WithStack(err)
			}
			store.head = genisis.Hash
			return txn.Set(genisis.Hash, rawBlock)
		}

		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			store.head = val
			return nil
		})
	})
	return store, err
}

// BlockStore is a ledger stored on disk.
type BlockStore struct {
	db   *badger.DB
	head []byte
}

// Push will create a new block and push it onto the internal stack
func (bs *BlockStore) Push(data []byte) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		head := &block.Block{}
		err := initBlock(txn, bs.head, head)
		if err != nil {
			return errors.WithStack(err)
		}
		next := head.CreateNext(data)
		raw, err := proto.Marshal(next)
		if err != nil {
			return errors.WithStack(err)
		}
		bs.head = next.Hash
		return txn.Set(next.Hash, raw)
	})
}

// AddBlock will add a block with an array of transactions.
func (bs *BlockStore) AddBlock(txs []*block.Transaction) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		next := block.New(txs, bs.head)
		raw, err := proto.Marshal(next)
		if err != nil {
			return errors.WithStack(err)
		}
		bs.head = next.Hash
		return txn.Set(next.Hash, raw)
	})
}

// CheckValid will traverse the list of blocks and check that
// non of the hashes have been changed.
func (bs *BlockStore) CheckValid() (ok bool, err error) {
	ok = false
	err = bs.db.View(func(txn *badger.Txn) error {
		var prev []byte
		head := &block.Block{}
		err := initBlock(txn, bs.head, head)
		if err != nil {
			return err
		}
		if bytes.Compare(head.Hash, bs.head) != 0 {
			return nil
		}
		// while head is not first after genisis,
		// traverse the chain backward
		for !block.IsGenisis(head) {
			prev = head.PrevHash
			err = initBlock(txn, head.PrevHash, head)
			if err != nil {
				return err
			}
			// if the hashes are not the same then something
			// changed, set to not ok and stop
			if bytes.Compare(head.Hash, prev) != 0 {
				return nil
			}
		}
		ok = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return ok, err
}

// Transaction will get a transaction by id
func (bs *BlockStore) Transaction(id []byte) *block.Transaction {
	var (
		it  = blockIter{next: bs.head, txn: bs.db.NewTransaction(false)}
		blk *block.Block
	)
	defer it.Close()
	for {
		blk = it.Next()
		for _, tx := range blk.Transactions {
			if bytes.Compare(id, tx.ID) == 0 {
				return tx
			}
		}
		if block.IsGenisis(blk) {
			return nil
		}
	}
}

// Iter will return a block iterator.
func (bs *BlockStore) Iter() block.Iterator {
	return &blockIter{
		next: bs.head,
		txn:  bs.db.NewTransaction(false),
	}
}

// Blocks will return a channel generator that returns
// the blocks in the chain
func (bs *BlockStore) Blocks() <-chan *block.Block {
	key := bs.head
	ch := make(chan *block.Block)
	send := func(v []byte) error {
		b := &block.Block{}
		err := proto.Unmarshal(v, b)
		if err != nil {
			return err
		}
		ch <- b
		key = b.PrevHash
		return nil
	}
	go func() {
		defer close(ch)
		err := bs.db.View(func(txn *badger.Txn) error {
			for len(key) != 0 {
				itm, err := txn.Get(key)
				if err != nil {
					return err
				}
				itm.Value(send)
			}
			return nil
		})
		if err != nil {
			panic(err)
		}
	}()
	return ch
}

type blockIter struct {
	next []byte // next block hash
	txn  *badger.Txn
}

func (iter *blockIter) Close() error {
	if iter.txn != nil {
		iter.txn.Discard()
		iter.txn = nil
	}
	return nil
}

func (iter *blockIter) Next() *block.Block {
	blk := &block.Block{}
	err := initBlock(iter.txn, iter.next, blk)
	if err != nil {
		iter.Close()
		return nil
	}
	iter.next = blk.PrevHash
	return blk
}

// Close will close the block store
func (bs *BlockStore) Close() (err error) {
	if err = bs.db.Update(func(txn *badger.Txn) error {
		return txn.Set(headKey, bs.head)
	}); err != nil {
		return err
	}
	return bs.db.Close()
}

func initBlock(txn *badger.Txn, key []byte, b *block.Block) error {
	item, err := txn.Get(key)
	if err != nil {
		return err
	}
	return item.Value(func(val []byte) error {
		return proto.Unmarshal(val, b)
	})
}

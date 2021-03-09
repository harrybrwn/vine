package blockstore

import (
	"bytes"
	"time"

	badger "github.com/dgraph-io/badger/v2"
	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-vine/block"
	"github.com/harrybrwn/go-vine/internal/logging"
	"github.com/harrybrwn/go-vine/key"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	headKey     = []byte("head")
	blockPrefix = []byte("_block")
	txPrefix    = []byte("_tx")
)

// CreateEmpty creates a new database file
func CreateEmpty(dir string) error {
	opts := badger.DefaultOptions(dir)
	opts.Logger = logrus.StandardLogger()
	db, err := badger.Open(opts)
	if err != nil {
		return errors.WithStack(err)
	}
	return db.Close()
}

// Open will open an existing database
func Open(dir string, options ...Opt) (*BlockStore, error) {
	opts := badger.DefaultOptions(dir)
	logger := logging.Copy()
	logger.Formatter = &logging.PrefixedFormatter{
		Prefix:     "block-storage",
		TimeFormat: time.RFC3339,
	}
	opts.Logger = logger

	for _, o := range options {
		o(&opts)
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	opts.Logger.Debugf("blockstore opened at %s", dir)

	var head []byte
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(headKey)
		if err == badger.ErrKeyNotFound {
			return nil
		} else if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			head = v
			return nil
		})
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BlockStore{db: db, head: head, opts: &opts}, nil
}

// New creates a new BlockStore
func New(address key.Address, dir string) (*BlockStore, error) {
	logrus.Warn("blockstore.New is deprecated")
	opts := badger.DefaultOptions(dir)
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	store := &BlockStore{db: db, opts: &opts}

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
			return txn.Set(withBlockPrefix(genisis.Hash), rawBlock)
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
	opts *badger.Options
}

// Push will add a block the the blockchain and update the
// database head hash. If the block has not been mined, then
// an error will be returned.
func (bs *BlockStore) Push(blk *block.Block) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		return bs.pushBlock(blk, txn)
	})
}

// PushBlocks adds a list of blocks to the chain.
func (bs *BlockStore) PushBlocks(blocks []*block.Block) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		for _, blk := range blocks {
			err := bs.pushBlock(blk, txn)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (bs *BlockStore) pushBlock(blk *block.Block, txn *badger.Txn) error {
	if !block.HasDoneWork(blk) {
		return block.ErrBlockNotMined
	}
	raw, err := proto.Marshal(blk)
	if err != nil {
		return errors.WithStack(err)
	}
	err = txn.Set(withBlockPrefix(blk.Hash), raw)
	if err == nil {
		bs.head = blk.Hash
	}
	return err
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

// Get will return a block given the block's hash as a key
func (bs *BlockStore) Get(hash []byte) (*block.Block, error) {
	blk := new(block.Block)
	return blk, bs.db.View(func(txn *badger.Txn) error {
		return initBlock(txn, hash, blk)
	})
}

// HeadHash returns the head hash (the hash of the last block to be stored)
func (bs *BlockStore) HeadHash() []byte {
	return bs.head
}

// Head will return the block stored at the head
func (bs *BlockStore) Head() (*block.Block, error) {
	b := new(block.Block)
	return b, bs.db.View(func(txn *badger.Txn) error {
		return initBlock(txn, bs.head, b)
	})
}

func (bs *BlockStore) getHeadBlock(txn *badger.Txn) (*block.Block, error) {
	head := &block.Block{}
	return head, initBlock(txn, bs.head, head)
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
			if !block.HasDoneWork(head) {
				return block.ErrBlockNotMined
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
		tx  *block.Transaction
		blk *block.Block
	)
	// First, check if the transaction has been saved
	// in the database
	err := bs.db.View(func(txn *badger.Txn) error {
		itm, err := txn.Get(withTxPrefix(id))
		if err != nil {
			return err
		}
		return itm.Value(func(val []byte) error {
			return proto.Unmarshal(val, tx)
		})
	})
	if err == nil {
		return tx
	}

	// If the transaction was not found in the database
	// then we will iterate through all the blocks to find it
	it := blockIter{next: bs.head, txn: bs.db.NewTransaction(false)}
	defer it.Close()
	for {
		blk = it.Next()
		for _, tx = range blk.Transactions {
			if bytes.Compare(id, tx.ID) == 0 {
				return tx
			}
		}
		if block.IsGenisis(blk) {
			return nil
		}
	}
}

func initBlock(txn *badger.Txn, key []byte, b *block.Block) error {
	item, err := txn.Get(withBlockPrefix(key))
	if err != nil {
		return err
	}
	return item.Value(func(val []byte) error {
		return proto.Unmarshal(val, b)
	})
}

func withBlockPrefix(key []byte) []byte {
	return bytes.Join([][]byte{blockPrefix, key}, nil)
}

func withTxPrefix(key []byte) []byte {
	return bytes.Join([][]byte{txPrefix, key}, nil)
}

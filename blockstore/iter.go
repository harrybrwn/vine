package blockstore

import (
	badger "github.com/dgraph-io/badger/v2"
	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/block"
)

// Iter will return a block iterator.
func (bs *BlockStore) Iter() block.Iterator {
	return &blockIter{
		next: bs.head,
		txn:  bs.db.NewTransaction(false),
	}
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
				itm, err := txn.Get(withBlockPrefix(key))
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

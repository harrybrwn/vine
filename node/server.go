package node

import (
	"context"
	"encoding/hex"

	"github.com/harrybrwn/go-vine/block"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type rpcHandler struct {
	UnimplementedBlockStoreServer
}

// Head implement the Head service for the BlockStoreServer grpc service.
func (n *Node) Head(ctx context.Context, e *Empty) (*BlockMsg, error) {
	log.Info("rpc Head")
	blk, err := n.store.Head()
	if err != nil {
		return nil, err
	}
	return &BlockMsg{Sender: n.host.ID().Pretty(), Block: blk}, nil
}

// Base is receive requests for the base of the blockchain.
func (n *Node) Base(ctx context.Context, e *Empty) (*BlockMsg, error) {
	log.Info("rpc Base")
	it := n.store.Iter()
	for {
		blk := it.Next()
		if blk == nil {
			break
		}
		if block.IsGenisis(blk) {
			return &BlockMsg{Sender: n.host.ID().Pretty(), Block: blk}, nil
		}
	}
	return nil, errors.New("could not find genisis block")
}

// GetBlock implement the GetBlock service for the BlockStoreServer grpc service.
func (n *Node) GetBlock(ctx context.Context, req *BlockReq) (*BlockMsg, error) {
	log.Info("rpc GetBlock")
	blk, err := n.store.Get(req.Hash)
	if err != nil {
		return nil, err
	}
	return &BlockMsg{Sender: n.host.ID().Pretty(), Block: blk}, nil
}

// GetTx implement the GetTx service for the BlockStoreServer grpc service.
func (n *Node) GetTx(ctx context.Context, req *TxReq) (*TxMsg, error) {
	log.Info("rpc GetTx")
	tx := n.txdb.Transaction(req.Hash)
	if tx == nil {
		return nil, errors.New("could not find transaction")
	}
	return &TxMsg{Sender: n.host.ID().Pretty(), Tx: tx}, nil
}

// Tx implement the Tx service for the BlockStoreServer grpc service.
func (n *Node) Tx(ctx context.Context, msg *TxMsg) (*Status, error) {
	log.WithFields(log.Fields{
		"from":    msg.Sender,
		"tx.hash": hex.EncodeToString(msg.Tx.ID),
		"tx.lock": msg.Tx.Lock,
		"tx.fee":  msg.Tx.GetFee(n.txdb),
	}).Info("rpc Tx")
	err := msg.Tx.VerifySig(n.txdb)
	if err != nil {
		log.WithError(err).Warn("could not verify new tx signagure")
	}

	// TODO follow the following logic instead of just adding the block

	// If we have seen this tx hash before, then
	//     we skip and return OK
	// If we have not seen this tx, then
	//     we store it in a pending transaction pool
	//     and send it to our peers

	head, err := n.store.Head()
	if err != nil {
		return nil, err
	}
	blk := block.New([]*block.Transaction{msg.Tx}, head.Hash)
	return &Status{Code: Status_Ok}, n.store.Push(blk)
}

// Mined implement the Mined service for the BlockStoreServer grpc service.
func (n *Node) Mined(ctx context.Context, msg *BlockMsg) (*Status, error) {
	log.WithFields(log.Fields{"from": msg.Sender}).Info("rpc Mined")
	return nil, nil
}

var _ BlockStoreServer = (*Node)(nil)

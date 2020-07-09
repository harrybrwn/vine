package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/key"
)

type txHead struct {
	from   key.Sender
	to     key.Receiver
	amount int64
}

type chainStats struct {
	// mapping of transaction IDs to spendable output indexes
	spendable map[string][]int
	// mapping of user addresses to user balances
	balances map[string]int64

	// maps transaction IDs to spent output indexes
	spent   map[string][]int
	unspent []*Transaction
	utxo    map[string][]*TxOutput
}

func initTransaction(finder TxFinder, stats *chainStats, header txHead, tx *Transaction) (err error) {
	senderBal, spendable := stats.spendableTxOutputs(header.from, header.amount)
	for txid, outIDs := range spendable {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			return err
		}
		for _, out := range outIDs {
			tx.Inputs = append(tx.Inputs, &TxInput{
				TxID:      txID,
				OutIndex:  int32(out),
				Signature: nil,
				PubKey:    header.from.PublicKey(),
			})
		}
	}
	err = addOutput(tx, header.from.PubKeyHash(), senderBal, header.to, header.amount)
	if err != nil {
		return err
	}
	tx.ID = tx.hash()
	// reset the stats for utxo's
	stats.utxo[hex.EncodeToString(header.from.PubKeyHash())] = tx.Outputs

	prevtxs := make(map[string]*Transaction)
	for _, in := range tx.Inputs {
		prev := finder.Transaction(in.TxID)
		if prev == nil {
			log.Printf("could not find previous tx %s\n", in.TxID)
			continue
		}
		prevtxs[prev.StrID()] = prev
	}
	return tx.Sign(header.from.PrivateKey(), prevtxs)
}

func addOutput(
	tx *Transaction,
	senderPubKHash []byte,
	senderBal int64,
	to key.Receiver,
	amount int64,
) error {
	if senderBal < amount {
		return ErrNotEnoughFunds
	}
	tx.Outputs = append(tx.Outputs, &TxOutput{
		Amount:     amount,
		PubKeyHash: key.ExtractPubKeyHash(to.Address()),
	})
	if senderBal > amount {
		tx.Outputs = append(tx.Outputs, &TxOutput{
			Amount:     senderBal - amount,
			PubKeyHash: senderPubKHash,
		})
	}
	return nil
}

// NewTransaction will create a new transaction.
func _newTransaction(chain Chain, to key.Receiver, from key.Sender, amount int64) (tx *Transaction, err error) {
	stats := buildChainStats(chain.Iter())
	bal, validOutputs := stats.spendableTxOutputs(from, amount)
	if bal < amount {
		return nil, ErrNotEnoughFunds
	}
	tx = &Transaction{
		Inputs:  make([]*TxInput, len(validOutputs)),
		Outputs: make([]*TxOutput, 0),
	}

	for txidStr, outIDs := range validOutputs {
		txID, err := hex.DecodeString(txidStr)
		if err != nil {
			return nil, err
		}
		for i, out := range outIDs {
			tx.Inputs[i] = &TxInput{
				TxID:      txID,
				OutIndex:  int32(out),
				Signature: nil,
				PubKey:    from.PublicKey(),
			}
		}
	}
	err = addOutput(tx, from.PubKeyHash(), bal, to, amount)
	if err != nil {
		return tx, err
	}
	tx.ID = tx.hash()

	prevtxs := make(map[string]*Transaction)
	for _, in := range tx.Inputs {
		prev := chain.Transaction(in.TxID)
		if prev == nil {
			continue
		}
		prevtxs[prev.StrID()] = prev
	}
	return tx, tx.Sign(from.PrivateKey(), prevtxs)
}

// UnspentTx will return the unspent transactions for a user address
func _unspentTx(chain Iterator, pubkeyhash []byte) []*Transaction {
	// TODO: add a persistance layer that stores unspent transactions by public key
	var (
		spent   = make(map[string][]int)
		unspent []*Transaction
		block   *Block
	)

	for {
		block = chain.Next()
		for _, tx := range block.Transactions {
			txid := tx.StrID()
		NextOut:
			for outID, out := range tx.Outputs {
				// if the transaction has spent outputs
				// then we check that none of them are the
				// current output
				if spentTxIDs, ok := spent[txid]; ok {
					for _, spentTxID := range spentTxIDs {
						if spentTxID == outID {
							// go to the next output if the
							// current output is in the transaction's
							// list of spent outputs
							continue NextOut
						}
					}
				}
				// if it is not spent and is owned by the user
				// with the address then grab a copy of the transaction.
				if out.isLockedWith(pubkeyhash) {
					unspent = append(unspent, cloneTx(tx))
				}
			}

			// Inputs of a coinbase transactions do not reference an output.
			// https://en.bitcoin.it/wiki/Transaction#Generation
			if !tx.IsCoinbase() {
				for _, input := range tx.Inputs {
					inID := hex.EncodeToString(input.TxID)
					spent[inID] = append(spent[inID], int(input.OutIndex))
				}
			}
		}
		if IsGenisis(block) {
			break
		}
	}
	return unspent
}

func buildChainStats(it Iterator) *chainStats {
	var (
		block   *Block
		userkey string
		s       = &chainStats{
			spendable: make(map[string][]int),
			balances:  make(map[string]int64),
			spent:     make(map[string][]int),
			unspent:   make([]*Transaction, 0),
			utxo:      make(map[string][]*TxOutput),
		}
	)

	for {
		block = proto.Clone(it.Next()).(*Block)
		for _, tx := range block.Transactions {
			txid := tx.StrID()
			for outIx, out := range tx.Outputs {
				// check if the current transaction output index
				// has been stored in the spent tx outputs
				if s.txOutputIsSpent(txid, outIx) {
					continue
				}

				// If the output has not been referenced by a previous input
				// then we can add it the unspent transaction outputs and
				// count the amount sent to that public key hash.
				s.spendable[txid] = append(s.spendable[txid], outIx)
				userkey = hex.EncodeToString(out.PubKeyHash)
				if _, ok := s.balances[userkey]; !ok {
					s.balances[userkey] = 0
				}
				s.balances[userkey] += out.Amount
				s.unspent = append(s.unspent, tx)
				s.utxo[userkey] = append(s.utxo[userkey], out)
			}

			// Inputs of a coinbase transactions do not reference an output.
			// https://en.bitcoin.it/wiki/Transaction#Generation
			if !tx.IsCoinbase() {
				for _, in := range tx.Inputs {
					inID := hex.EncodeToString(in.TxID)
					s.spent[inID] = append(s.spent[inID], int(in.OutIndex))
				}
			}
		}
		if IsGenisis(block) {
			break
		}
	}
	return s
}

func (sts *chainStats) bal(user key.Receiver) (bal int64) {
	pubkh := key.ExtractPubKeyHash(user.Address())
	key := hex.EncodeToString(pubkh)
	for _, out := range sts.utxo[key] {
		bal += out.Amount
	}
	return bal
	// return sts.balances[hex.EncodeToString(key.ExtractPubKeyHash(user.Address()))]
}

func (sts *chainStats) txOutputIsSpent(txid string, index int) bool {
	if spentouts, ok := sts.spent[txid]; ok {
		for _, ix := range spentouts {
			if ix == index {
				return true
			}
		}
	}
	return false
}

// SpendableTxOutputs returns a user's balance and spendable outputs.
// user is the user that will be spending the outputs and
// cap is the amount cap that they are trying to spend
func (sts *chainStats) spendableTxOutputs(user key.Receiver, cap int64) (spendable int64, spOuts map[string][]int) {
	var (
		txid  string
		pubkh = key.ExtractPubKeyHash(user.Address())
	)
	spOuts = make(map[string][]int)
	for _, tx := range sts.unspent {
		txid = tx.StrID()
		for oid, out := range tx.Outputs {
			if !out.isLockedWith(pubkh) {
				continue
			}
			if spendable <= cap {
				spendable += out.Amount
				spOuts[txid] = append(spOuts[txid], oid)
				if spendable >= cap {
					return
				}
			}
		}
	}
	return
}

// Sign signs a tx
func (tx *Transaction) Sign(key *ecdsa.PrivateKey, prevtx map[string]*Transaction) error {
	if tx.IsCoinbase() {
		return nil
	}
	txcp := cloneTx(tx)
	for i, input := range txcp.Inputs {
		prev, ok := prevtx[hex.EncodeToString(input.TxID)]
		if !ok || prev.ID == nil {
			return errors.New("transaction does not exist")
		}
		input.Signature = nil
		if int(input.OutIndex) >= len(txcp.Outputs) {
			fmt.Println("outindex:", input.OutIndex, ", input len:", len(txcp.Outputs))
			fmt.Println(hex.EncodeToString(prev.ID))
			return errors.New("invalid transaction output index")
		}
		input.PubKey = txcp.Outputs[input.OutIndex].PubKeyHash
		txcp.ID = txcp.hash()
		txcp.Inputs[i].PubKey = nil
		r, s, err := ecdsa.Sign(rand.Reader, key, txcp.ID)
		if err != nil {
			return err
		}
		txcp.Inputs[i].Signature = bytes.Join([][]byte{r.Bytes(), s.Bytes()}, nil)
	}
	return nil
}

// IsCoinbase will return true of the transaction
// is a coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && len(tx.Outputs) == 1 && tx.Inputs[0].OutIndex < 0
}

// StrID will return a hex encoded version of the transaction ID
func (tx *Transaction) StrID() string {
	return hex.EncodeToString(tx.ID)
}

func (tx *Transaction) hash() []byte {
	b, err := proto.Marshal(tx)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func newTxOutput(amount int64, to string) *TxOutput {
	return &TxOutput{Amount: amount, PubKeyHash: key.ExtractPubKeyHash(to)}
}

func (out *TxOutput) lock(address string) {
	out.PubKeyHash = key.ExtractPubKeyHash(address)
}

func (out *TxOutput) isLockedWith(pubkeyhash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubkeyhash) == 0
}

func (in *TxInput) useskey(pubkeyhash []byte) bool {
	lockHash := key.PubKey(in.PubKey).Hash()
	return bytes.Compare(lockHash, pubkeyhash) == 0
}

func cloneTx(t *Transaction) *Transaction {
	return proto.Clone(t).(*Transaction)
}

func hexAddrKey(user key.Receiver) string {
	return hex.EncodeToString(key.ExtractPubKeyHash(user.Address()))
}

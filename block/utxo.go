package block

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"

	"github.com/harrybrwn/go-ledger/key"
)

// UTXOSet holds unspent transaction outputs.
type UTXOSet interface {
	Bal(key.Address) uint64
	Unspent(key.Address) []*UTXO
	Update(*Transaction) error
	// TODO add a 'Spent' function that will
	// mark spent transaction outputs as spent
}

// BuildUTXOSet will traverse the entire chain to
// build an indexed unspent transaction set
func BuildUTXOSet(i Iterator) UTXOSet {
	return buildChainStats(i)
}

// UTXO is an unspent transaction output
// This is the same as a TxOutput except
// it holds usfule information for creating
// transaction inputs like the output index
// and the transaction ID.
type UTXO struct {
	*TxOutput
	index int
	txid  []byte
}

type chainStats struct {
	// mapping of user addresses to user balances
	balances map[string]uint64
	// maps transaction IDs to spent output indexes
	spent map[string][]int32
	// maps user pub-key-hashes to unspent outputs
	utxo map[string][]*UTXO
}

func (sts *chainStats) Update(tx *Transaction) error {
	var (
		userkey string
		txid    = tx.StrID()
	)
	// Dummy check
	if len(txid) == 0 {
		return errors.New("transaction has no ID")
	}
	for outIx, out := range tx.Outputs {
		// check if the current transaction output index
		// has been stored in the spent tx outputs
		if sts.txOutputIsSpent(txid, int32(outIx)) {
			continue
		}

		// If the output has not been referenced by a previous
		// input then we can add it the unspent transaction
		// outputs and count the amount sent to that public
		// key hash.
		userkey = hex.EncodeToString(out.PubKeyHash)
		if _, ok := sts.balances[userkey]; !ok {
			sts.balances[userkey] = 0
		}
		sts.balances[userkey] += out.Amount
		sts.utxo[userkey] = append(sts.utxo[userkey], &UTXO{
			TxOutput: out,
			index:    outIx,
			txid:     tx.ID,
		})
	}

	// Inputs of a coinbase transactions do not reference
	// an output.
	// https://en.bitcoin.it/wiki/Transaction#Generation
	if !tx.IsCoinbase() {
		for _, in := range tx.Inputs {
			sts.markSpent(in.TxID, in.OutIndex)
		}
	}
	return nil
}

func buildChainStats(it Iterator) *chainStats {
	var (
		block *Block
		s     = &chainStats{
			spent:    make(map[string][]int32),
			balances: make(map[string]uint64),
			utxo:     make(map[string][]*UTXO),
		}
	)

	for {
		block = it.Next()
		for _, tx := range block.Transactions {
			if err := s.Update(tx); err != nil {
				panic(err) // TODO handle this
			}
		}
		if IsGenisis(block) {
			if ic, ok := it.(io.Closer); ok {
				ic.Close()
			}
			break
		}
	}
	return s
}

func (sts *chainStats) Bal(user key.Address) (bal uint64) {
	key := hex.EncodeToString(user.PubKeyHash())
	return sts.balances[key]
}

func (sts *chainStats) Unspent(k key.Address) []*UTXO {
	utxos := sts.utxo[hex.EncodeToString(k.PubKeyHash())]
	return utxos
}

func (sts *chainStats) markSpent(txid []byte, index int32) {
	id := hex.EncodeToString(txid)
	sts.spent[id] = append(sts.spent[id], index)
}

func (sts *chainStats) txOutputIsSpent(
	txid string,
	index int32,
) bool {
	if spentouts, ok := sts.spent[txid]; ok {
		for _, ix := range spentouts {
			if ix == index {
				return true
			}
		}
	}
	return false
}

// FindOutputsToSpend will find unspent transaction
// outputs needed for a transaction Assumes that
// the balance has already been checked and the
// publickeyhash owns enough outputs
//
// This function assumes that the sender has enough
// funds to meet the quota.
func FindOutputsToSpend(
	set UTXOSet,
	sender key.Address,
	amountNeeded uint64,
) []*UTXO {
	var (
		result     = make([]*UTXO, 0)
		current    uint64                // current amount outputted via UTXOs
		allunspent = set.Unspent(sender) // all the sender's UTXOs
	)
	for _, o := range allunspent {
		// If a single output can be used
		// then return that one output.
		if o.Amount >= amountNeeded {
			return []*UTXO{o}
		}

		// if we have already found the outputs needed
		// to meet the amount needed then we just
		// keep scanning the UTXOs for single outputs
		// that could possiblly meet that quota.
		if current < amountNeeded {
			current += o.Amount
			result = append(result, o)
		}
	}
	if len(result) == 0 {
		// dummy check. this should not happen
		// given the assumtions
		panic("no outputs to meet quota")
	}
	return result
}

// Spend is the same as FindOutputsToSpend except it also
// removed the them from the set of unspent transaction outputs.
func (sts *chainStats) spend(sender key.Address, amount uint64) []*UTXO {
	address := hex.EncodeToString(sender.PubKeyHash())
	spentouts := FindOutputsToSpend(sts, sender, amount)
	unspent := sts.utxo[address]
	sts.utxo[address] = make([]*UTXO, 0, len(unspent))

Outer:
	for _, o := range unspent {
		for _, spent := range spentouts {
			if utxoEq(spent, o) {
				txid := hex.EncodeToString(spent.txid)
				sts.spent[txid] = append(sts.spent[txid], int32(spent.index))
				continue Outer
			}
		}
		sts.utxo[address] = append(sts.utxo[address], o)
	}

	return spentouts
}

func utxoEq(a, b *UTXO) bool {
	return a.index == b.index &&
		a.Amount == b.Amount &&
		bytes.Compare(a.txid, b.txid) == 0 &&
		bytes.Compare(a.PubKeyHash, b.PubKeyHash) == 0
}

package block

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"

	"github.com/harrybrwn/vine/key"
)

// UTXOSet holds unspent transaction outputs.
type UTXOSet interface {
	Bal(key.Address) uint64
	Unspent(key.Address) []*UTXO
	Update(*Transaction) error
	ReIndex(Iterator) error
}

// BuildUTXOSet will traverse the entire chain to
// build an indexed unspent transaction set
func BuildUTXOSet(it Iterator) UTXOSet {
	var set = &chainStats{
		spent:    make(map[string][]int),
		balances: make(map[string]uint64),
		utxo:     make(map[string][]*UTXO),
	}
	if err := set.ReIndex(it); err != nil {
		panic(err) // TODO handle this or make sure it doesn't happen
	}
	return set
}

// UTXO is an unspent transaction output
// This is the same as a TxOutput except
// it holds useful information for creating
// transaction inputs like the output index
// and the transaction ID.
type UTXO struct {
	// The actual transaction output that
	// has not been spent
	*TxOutput
	// Stores the info for creating a new
	// input from the unspent output
	index int
	txid  []byte
}

type chainStats struct {
	// mapping of user addresses to user balances
	balances map[string]uint64
	// maps transaction IDs to spent output indexes
	spent map[string][]int
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
	// Inputs of a coinbase transactions do not reference
	// an output.
	// https://en.bitcoin.it/wiki/Transaction#Generation
	if !tx.IsCoinbase() {
		for _, in := range tx.Inputs {
			sts.markSpent(in.TxID, int(in.OutIndex), in.PubKey)
		}
	}

	for outIx, out := range tx.Outputs {
		// check if the current transaction output index
		// has been stored in the spent tx outputs
		if sts.txOutputIsSpent(txid, outIx) {
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
	return nil
}

func (sts *chainStats) ReIndex(it Iterator) error {
	var block *Block
	for {
		block = it.Next()
		for _, tx := range block.Transactions {
			if err := sts.Update(tx); err != nil {
				return err
			}
		}
		if IsGenisis(block) {
			if ic, ok := it.(io.Closer); ok {
				return ic.Close()
			}
			break
		}
	}
	return nil
}

func (sts *chainStats) Bal(user key.Address) (bal uint64) {
	key := hex.EncodeToString(user.PubKeyHash())
	return sts.balances[key]
}

func (sts *chainStats) Unspent(k key.Address) []*UTXO {
	utxos := sts.utxo[hex.EncodeToString(k.PubKeyHash())]
	return utxos
}

func (sts *chainStats) markSpent(txid []byte, index int, pubkey []byte) {
	id := hex.EncodeToString(txid)
	sts.spent[id] = append(sts.spent[id], index)
	userkey := hex.EncodeToString(key.PubKey(pubkey).Hash())

	// Save a copy of the user's UTXOs to modify later
	// and check that the user actually does exist in the set
	unspent, ok := sts.utxo[userkey]
	if !ok {
		return
	}

	// update the utxo set by checking if the output being marked as
	// spent is in it and removing it then updating the balance set
	for i, utxo := range sts.utxo[userkey] {
		if utxo.index == int(index) && bytes.Compare(utxo.txid, txid) == 0 {
			// update balance and remove from list of UTXOs
			sts.balances[userkey] -= utxo.Amount
			unspent = remove(unspent, i)
		}
	}
	// reset the UTXOs
	sts.utxo[userkey] = unspent
}

func remove(s []*UTXO, index int) []*UTXO {
	l := len(s) - 1
	s[index] = s[l] // swap
	return s[:l]    // exclude
}

func (sts *chainStats) txOutputIsSpent(
	txid string,
	index int,
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

// FindOutputsToSpend will find unspent transaction outputs
// needed for a transaction. Guaranteed to return at least
// one UTXO and a combined value greater than or equal to
// the amount needed (given as an argument). Assumes that
// the balance has already been checked and the publickeyhash
// owns enough outputs.
//
// This function assumes that the sender has enough
// funds to meet the quota.
func FindOutputsToSpend(
	set UTXOSet,
	sender key.Address,
	amountNeeded uint64,
) []*UTXO {
	var (
		current    uint64                // current amount outputted via UTXOs
		allunspent = set.Unspent(sender) // all the sender's UTXOs
		result     = make([]*UTXO, 0)
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
		// that could possibly meet that quota.
		if current < amountNeeded {
			current += o.Amount
			result = append(result, o)
		}
	}
	if len(result) == 0 {
		// dummy check. this should not happen
		// given the assumptions
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
				sts.spent[txid] = append(sts.spent[txid], spent.index)
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

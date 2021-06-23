package mockblock

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/golang/protobuf/ptypes"
	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/key"
)

type userinfo struct {
	user key.Sender
	name string
}

type chaindebugger struct {
	m map[string]userinfo
	w io.Writer
}

func NewChainDebugger(w io.Writer, users []key.Sender) *chaindebugger {
	dbg := chaindebugger{
		w: w,
		m: make(map[string]userinfo),
	}
	for _, u := range users {
		dbg.AddUser(u)
	}
	return &dbg
}

func (dbg *chaindebugger) AddUser(u key.Sender) {
	key := u.PubKeyHash()
	dbg.m[hex.EncodeToString(key)] = userinfo{
		user: u,
		name: fmt.Sprintf("user(%d)", len(dbg.m)),
	}
}

func (dbg *chaindebugger) addUserPubkeyHash(hash []byte) {
	dbg.m[hex.EncodeToString(hash)] = userinfo{
		name: fmt.Sprintf("new-user(%d)", len(dbg.m)),
	}
}

func (dbg *chaindebugger) hasUser(key []byte) bool {
	_, ok := dbg.m[hex.EncodeToString(key)]
	return ok
}

func (dbg chaindebugger) PrintChain(it block.Iterator) {
	var w = dbg.w
	if w == nil {
		w = os.Stdout
	}
	for {
		blk := it.Next()
		if blk == nil {
			break
		}

		fmt.Fprintf(w, "Block(%.10x...)\n", blk.GetHash())
		for _, tx := range blk.GetTransactions() {
			fmt.Fprintf(w, "  TX(%.10x)\n", tx.ID)
			fmt.Fprintf(w, "    lock: %v,\n", ptypes.TimestampString(tx.Lock))
			const trunc = 10
			for _, in := range tx.Inputs {
				fmt.Fprintf(w, "    In(")
				var hash []byte = nil
				if in.PubKey != nil {
					hash = key.PubKey(in.PubKey).Hash()
				}
				if !dbg.hasUser(hash) {
					dbg.addUserPubkeyHash(hash)
				}
				fmt.Fprintf(w, "user:  %s, ", dbg.name(hash))
				fmt.Fprintf(w, "index: %-d, ", in.OutIndex)
				fmt.Fprintf(w, "tx: %.10x, ", in.TxID)
				fmt.Fprintf(w, "pubhash: %.10x, ", hash)
				fmt.Fprintf(w, "pubkey: %.10x, ", in.PubKey)
				fmt.Fprintf(w, "sig: %.10x, ", in.Signature)
				fmt.Fprintf(w, "\b\b)\n")
			}

			for i, out := range tx.Outputs {
				if !dbg.hasUser(out.PubKeyHash) {
					dbg.addUserPubkeyHash(out.PubKeyHash)
				}
				fmt.Fprintf(w, "    Out(")
				fmt.Fprintf(w, "user: %s, ", dbg.name(out.PubKeyHash))
				if dbg.name(out.PubKeyHash) == "" {
					fmt.Printf("\n%x\n", out.PubKeyHash)
				}
				fmt.Fprintf(w, "index: %-d, ", i)
				fmt.Fprintf(w, "amount: %d, ", out.Amount)
				fmt.Fprintf(w, "pubhash: %.10x, ", out.PubKeyHash)
				fmt.Fprintf(w, "\b\b)\n")
			}
		}
		fmt.Fprintf(w, "\n")
		if block.IsGenisis(blk) {
			break
		}
	}
	fmt.Fprintf(w, "End Chain")
}

func (dbg chaindebugger) inputStr(in *block.TxInput) string {
	return fmt.Sprintf("In(tx: %.10x, ", in.TxID)
}

func (dbg chaindebugger) name(pubkeyhash []byte) string {
	if pubkeyhash == nil {
		return "<none>"
	}
	return dbg.m[hex.EncodeToString(pubkeyhash)].name
}

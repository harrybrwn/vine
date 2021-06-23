package block_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/harrybrwn/vine/internal/mockblock"
	"github.com/harrybrwn/vine/internal/testutil"
	"github.com/harrybrwn/vine/key"
)

func init() {
	testutil.Deterministic = true
}

func TestRandomized(t *testing.T) {
	t.Skip()
	users := []key.Sender{
		testutil.Wallet(t, 1),
		testutil.Wallet(t, 2),
		testutil.Wallet(t, 3),
		testutil.Wallet(t, 4),
		testutil.Wallet(t, 5),
		testutil.Wallet(t, 6),
		testutil.Wallet(t, 7),
		testutil.Wallet(t, 8),
		testutil.Wallet(t, 9),
		testutil.Wallet(t, 10),
		testutil.Wallet(t, 11),
		testutil.Wallet(t, 12),
	}
	e := mockblock.NewEngine(t, mockblock.NewChain(users[0]), users)
	err := e.Step(10)
	if err != nil {
		t.Error(err)
	}
	// e.SetSeed(1)
	// dbg := mockblock.NewChainDebugger(os.Stdout, users)
	// dbg.PrintChain(e.Chain.Iter())
	fmt.Println(strings.Repeat("-", 80))
	for _, u := range users {
		fmt.Println(e.UTXO.Bal(u))
	}
}

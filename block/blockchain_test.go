package block_test

import (
	"testing"

	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/internal/mockblock"
	"github.com/harrybrwn/go-ledger/key/wallet"
)

func TestTx(t *testing.T) {
	user1, user2 := wallet.New(), wallet.New()
	// fmt.Println("user1:", hex.EncodeToString(user1.PubKeyHash()))
	// fmt.Println("user2:", hex.EncodeToString(user2.PubKeyHash()))
	// println()
	chain := mockblock.NewChain(user1)
	err := chain.Push([]block.TxDesc{
		{From: user1, To: user2, Amount: 5},
		// {From: user1, To: user2, Amount: 10},
	})
	if err != nil {
		t.Error(err)
	}
	stats := block.ChainStats(chain.Iter())
	if bal := stats.Bal(user1); bal != 100-5 {
		t.Errorf("balance: expeced %d, got %d", 100-15, bal)
	}
	if bal := stats.Bal(user2); bal != 5 {
		t.Errorf("user2 has wrong balance: expected %d, got %d", 15, bal)
	}
}

package blockstore

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/sirupsen/logrus"
)

func init() { logrus.SetLevel(logrus.ErrorLevel) }

func TestNewBlockStore(t *testing.T) {
	store, dir, err := testStore(10, t)
	defer func() {
		store.Close()
		os.RemoveAll(dir)
	}()
	if err != nil {
		t.Error(err)
	}
	ok, err := store.CheckValid()
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("chain of hashes should be valid")
	}
	if err = store.Close(); err != nil {
		t.Error(err)
	}

	store, err = New(addr("tester"), dir)
	if err != nil {
		t.Error(err)
	}
	if len(store.head) == 0 {
		t.Fatal("store should have a head")
	}
	ok, err = store.CheckValid()
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("chain of hashes should be valid")
	}
	if err = store.Close(); err != nil {
		t.Error(err)
	}
}

func TestBlockIter(t *testing.T) {
	store, dir, err := testStore(10, t)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)
	iter := store.Iter()
	if err != nil {
		t.Error(err)
	}
	if iter == nil {
		t.Fatal("iterator should not be nil")
	}
	var b *block.Block
	b = iter.Next()
	var last []byte
	for b != nil {
		last = b.PrevHash
		b = iter.Next()
		if b == nil {
			break
		}
		if bytes.Compare(b.Hash, last) != 0 {
			t.Error("invalid hash")
		}
		if !block.IsGenisis(b) && !block.HasDoneWork(b) {
			t.Error("should have done PoW")
		}
	}

	for b = range store.Blocks() {
		if b == nil {
			t.Error("nil block")
		}
		if !block.IsGenisis(b) && !block.HasDoneWork(b) {
			t.Error("should have done PoW")
		}
	}
}

func TestUpdateStore(t *testing.T) {
}

const benchmarkBlocks = 4

func BenchmarkBasicIter(b *testing.B) {
	store, dir, err := testingStore(benchmarkBlocks)
	if err != nil {
		store.Close()
		os.RemoveAll(dir)
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		it := store.Iter()
		for {
			blk := it.Next()
			if block.IsGenisis(blk) {
				break
			}
		}
	}
	store.Close()
	os.RemoveAll(dir)
}

func BenchmarkIterWithChanner(b *testing.B) {
	store, dir, err := testingStore(benchmarkBlocks)
	if err != nil {
		store.Close()
		os.RemoveAll(dir)
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		ch := store.Blocks()
		for blk := range ch {
			if block.IsGenisis(blk) {
				break
			}
		}
	}
	store.Close()
	os.RemoveAll(dir)
}

func testStore(n int, t *testing.T) (*BlockStore, string, error) {
	t.Helper()
	if n <= 0 {
		n = 10
	}
	dir := tempdir()
	store, err := New(addr("tester"), dir)
	if err != nil {
		t.Error(err)
		return nil, dir, err
	}
	for i := 0; i < n; i++ {
		b := block.New(nil, store.HeadHash())
		err = store.Push(b)
		if err != nil {
			t.Error(err)
		}
	}
	return store, dir, nil
}

func testingStore(n int) (*BlockStore, string, error) {
	if n <= 0 {
		n = 10
	}
	dir := tempdir()
	store, err := New(addr("tester"), dir)
	if err != nil {
		return nil, dir, err
	}
	genisis := block.Genisis(block.Coinbase(wallet.New()))
	if err = store.Push(genisis); err != nil {
		return store, dir, err
	}
	for i := 0; i < n; i++ {
		b := block.New(nil, store.HeadHash())
		err = store.Push(b)
		if err != nil {
			return nil, dir, err
		}
	}
	return store, dir, nil
}

type addr string

func (a addr) Address() string {
	return string(a)
}

func tempdir() string {
	return filepath.Join(
		os.TempDir(),
		fmt.Sprintf("blockstore-%d", time.Now().Unix()),
	)
}

func testServer() (*http.Client, *http.ServeMux, *httptest.Server) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	transport := &testingTransport{&http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) { return url.Parse(srv.URL) },
	}}
	client := &http.Client{Transport: transport}
	return client, mux, srv
}

type testingTransport struct {
	tr http.RoundTripper
}

func (tt *testingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	if tt.tr == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return tt.tr.RoundTrip(req)
}

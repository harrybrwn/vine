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
)

func TestNewBlockStore(t *testing.T) {
	store, dir, err := testStore(t)
	defer os.RemoveAll(dir)
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

	store, err = New("tester", dir)
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
	store, dir, err := testStore(t)
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

func testStore(t *testing.T) (*BlockStore, string, error) {
	t.Helper()
	dir := tempdir()
	store, err := New("tester", dir)
	if err != nil {
		t.Error(err)
		return nil, dir, err
	}
	for i := 0; i < 10; i++ {
		b := block.New(nil, store.Head())
		err = store.Push(b)
		if err != nil {
			t.Error(err)
		}
	}
	return store, dir, nil
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

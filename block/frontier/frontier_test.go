package frontier

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

type hashable struct {
	hash []byte
	prev []byte
}

func (h *hashable) GetHash() []byte     { return h.hash }
func (h *hashable) GetPrevHash() []byte { return h.prev }

func newblock(data string, prev ...[]byte) *hashable {
	// hash := sha256.New()
	// hash.Write([]byte(data))
	// h := &hashable{hash: hash.Sum(nil), prev: nil}
	h := &hashable{hash: []byte(data)}
	if len(prev) > 0 {
		h.prev = prev[0]
	}
	return h
}

func Test(t *testing.T) {
}

func TestPush(t *testing.T) {
	var (
		err  error
		root = newblock("base")
		f    = New(root)
	)
	checkHash(t, f.root, []byte("base"))

	if err = collect(
		f.Push(newblock("root1", root.hash)),
		f.Push(newblock("root2", root.hash)),
	); err != nil {
		t.Fatal(err)
	}
	checkHash(t, f.root.children[0], []byte("root1"))
	checkHash(t, f.root.children[1], []byte("root2"))

	for i, prev := range [][]byte{
		f.root.children[0].hash,
		f.root.children[1].hash,
	} {
		for _, key := range []string{
			fmt.Sprintf("one_%d", i+1),
			fmt.Sprintf("two_%d", i+1),
			fmt.Sprintf("three_%d", i+1),
		} {
			err = f.Push(newblock(key, prev))
			if err != nil {
				t.Fatal(err)
			}
			prev = []byte(key)
		}
	}
	checkHash(t, f.root.children[1].children[0], []byte("one_2"))

	if err = f.Push(newblock("random-node", []byte("one_2"))); err != nil {
		t.Fatal(err)
	}
	checkHash(t, f.root.children[1].children[0].children[0], []byte("two_2"))
	checkHash(t, f.root.children[1].children[0].children[1], []byte("random-node"))
}

func checkHash(t *testing.T, n *node, exp []byte) bool {
	t.Helper()
	if !bytes.Equal(n.hash, exp) {
		t.Errorf("node has wrong hash: got %x, want %x", n.hash, exp)
		return false
	}
	return true
}

func printTree(n *node) {
	printNode(n, 0)
}

func printNode(n *node, depth int) {
	padding := strings.Repeat(" ", depth*4)
	fmt.Printf("%s%q {", padding, n.hash)
	if len(n.children) > 0 {
		fmt.Printf("\n")
		for _, child := range n.children {
			printNode(child, depth+1)
		}
		fmt.Printf("%s}", padding)
	} else {
		fmt.Printf("}")
	}
	if depth != 0 {
		fmt.Printf(",")
	}
	fmt.Printf("\n")
}

func collect(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

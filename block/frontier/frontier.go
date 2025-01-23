package frontier

import (
	"bytes"
	"errors"
)

type Hashable interface {
	GetHash() []byte
	GetPrevHash() []byte
}

type Frontier struct {
	root *node
}

func New(block Hashable) *Frontier {
	return &Frontier{
		root: newNode(block),
	}
}

type node struct {
	hash     []byte
	children []*node
}

func newNode(block Hashable) *node {
	return &node{
		hash:     block.GetHash(),
		children: make([]*node, 0),
	}
}

var (
	errNoPreviousHash = errors.New("no previous hash")
	errNotOnChain     = errors.New("block not found in chain set")
)

func (f *Frontier) Push(block Hashable) error {
	prev := block.GetPrevHash()
	if prev == nil {
		return errNoPreviousHash
	}
	if bytes.Equal(f.root.hash, prev) {
		f.root.children = append(f.root.children, newNode(block))
		return nil
	}
	q := newqueue(f.root.children...)
	for q.size() > 0 {
		child := q.pop()
		if bytes.Equal(child.hash, prev) {
			child.children = append(child.children, newNode(block))
			return nil
		}
		q.push(child.children...)
	}
	return errNotOnChain
}

type queue []*node

func newqueue(nodes ...*node) queue {
	q := make(queue, 0, len(nodes))
	q = append(q, nodes...)
	return q
}

func (q queue) size() int { return len(q) }

func (q *queue) push(n ...*node) { (*q) = append((*q), n...) }

func (q *queue) pop() *node {
	v := (*q)[0]
	(*q) = (*q)[1:]
	return v
}

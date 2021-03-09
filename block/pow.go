package block

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"

	"github.com/harrybrwn/errs"
)

type hashDifficulty uint16

var difficulty hashDifficulty = 19

// Hashable is an interface that defines
// type that can be hashed.
type Hashable interface {
	Hash() []byte
}

// Provable is defines an interface for
// block hashing
type Provable interface {
	GetTransactions() []*Transaction
	GetPrevHash() []byte
	GetData() []byte
}

// MabyeProved is an interface that has been
// previously run through the proof of work algorithm
type MabyeProved interface {
	Provable
	GetNonce() int64
}

// ProofOfWork runs the Proof of Work algorithm for a
// provable block.
func ProofOfWork(block Provable) (nonce int64, hash []byte) {
	var (
		// integer representation of the block hash
		inthash big.Int
		// 1 << (256-difficulty)
		target = new(big.Int).Lsh(big.NewInt(1), uint(256-difficulty))
	)
	// while nonce does not overflow
	for nonce < math.MaxInt64 {
		// use non-error-checking block hash as an optimization
		hash = hashBlock(difficulty, nonce, block)
		inthash.SetBytes(hash)
		// if inthash < target
		if inthash.Cmp(target) == -1 {
			// if the hash is less than the target then
			// then it has the desired number of leading zeros
			break
		}
		nonce++
	}
	return nonce, hash
}

// HasDoneWork returns true of the hash has been run through the proof of work
// algorithm.
func HasDoneWork(block MabyeProved) bool {
	var (
		inthash big.Int
		target  = new(big.Int).Lsh(big.NewInt(1), uint(256-difficulty))
	)
	// using the error checking function here because
	// checking work validity does not require many hashes,
	// so we don't need any optimizations
	hash, err := hashBlockE(difficulty, block.GetNonce(), block)
	if err != nil {
		panic(fmt.Sprintf("could not hash block: %v", err))
	}
	inthash.SetBytes(hash)
	// hash < target
	return inthash.Cmp(target) == -1
}

// hashBlockE will hash the block and check for errors
func hashBlockE(difficulty hashDifficulty, nonce int64, block Provable) ([]byte, error) {
	var (
		hash            = sha256.New()
		err, err1, err2 error
	)
	err1 = binary.Write(hash, binary.BigEndian, difficulty)
	err2 = binary.Write(hash, binary.BigEndian, nonce)
	if err = errs.Pair(err1, err2); err != nil {
		return hash.Sum(nil), err
	}
	merkleRoot, err := txMerkleRoot(block.GetTransactions())
	if err != nil {
		return hash.Sum(nil), err
	}
	_, err = hash.Write(merkleRoot)
	_, err1 = hash.Write(block.GetData())
	_, err2 = hash.Write(block.GetPrevHash())
	return hash.Sum(nil), errs.Chain(err, err1, err2)
}

// hashBlock is an optimized version of hashBlockE which does not
// check possible errors
func hashBlock(difficulty hashDifficulty, nonce int64, block Provable) []byte {
	hash, _ := hashBlockE(difficulty, nonce, block)
	return hash
}

func blockHashInt(inthash *big.Int, difficulty hashDifficulty, nonce int64, block Provable) error {
	var (
		hash            = sha256.New()
		err, err1, err2 error
	)
	err1 = binary.Write(hash, binary.BigEndian, difficulty)
	err2 = binary.Write(hash, binary.BigEndian, nonce)
	if err = errs.Pair(err1, err2); err != nil {
		return err
	}
	merkleRoot, err := txMerkleRoot(block.GetTransactions())
	if err != nil {
		return err
	}
	_, err = hash.Write(merkleRoot)
	_, err1 = hash.Write(block.GetData())
	_, err2 = hash.Write(block.GetPrevHash())
	inthash.SetBytes(hash.Sum(nil))
	return errs.Chain(err, err1, err2)
}

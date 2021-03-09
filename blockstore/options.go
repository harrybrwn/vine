package blockstore

import (
	badger "github.com/dgraph-io/badger/v2"
	"github.com/harrybrwn/go-vine/internal/logging"
)

// Opt is an option
type Opt func(*badger.Options)

// WithLogger is a blockstore option that will
// set the logger for the internal storage engine.
func WithLogger(l logging.Logger) Opt {
	return func(o *badger.Options) {
		o.Logger = l
	}
}

// SilentLogs is an blockstore option that will discard any
// logging done by the underlying storage engine.
func SilentLogs(o *badger.Options) {
	o.Logger = logging.Discard
}

// EncryptionKey will set the storage encryption key.
func EncryptionKey(key []byte) Opt {
	return func(o *badger.Options) {
		o.EncryptionKey = key
	}
}

// AsInMemory is an option that sets the
// database an an in-memory database.
func AsInMemory() Opt {
	return func(o *badger.Options) {
		o.InMemory = true
	}
}

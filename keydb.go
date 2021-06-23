package main

import (
	"fmt"
	"sync"
)

type keydb struct {
	keys map[string]*Key
	mu   sync.RWMutex
}

var db *keydb

// DB returns a keydb singleton
func DB() *keydb {

	if db == nil {
		db = &keydb{
			keys: make(map[string]*Key),
		}
	}

	return db
}

// GetKey returns a *Key by the kid
func (db *keydb) GetKey(kid string) (*Key, error) {

	db.mu.Lock()
	defer db.mu.Unlock()

	key, ok := db.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key does not exist in database")
	}
	return key, nil
}

// PutKey stores a new key
func (db *keydb) PutKey(key *Key) {

	db.mu.Lock()
	defer db.mu.Unlock()
	db.keys[key.kid] = key
}

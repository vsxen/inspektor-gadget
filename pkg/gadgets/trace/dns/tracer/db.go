// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

// dnsQueryKey is a unique identifier for a DNS queries. It contains the
// source IP address and the DNS transaction ID. The source IP address is
// stored as an array of 16 bytes to support both IPv4 and IPv6.
type dnsQueryKey struct {
	addr [16]uint8
	id   uint16
}

type dnsQueriesDataBase struct {
	sync.Mutex

	// chunkCap is the capacity of each chunk.
	chunkCap int

	// chunks is the number of chunks in the circular buffer.
	chunks int

	// newest is the index of the newest chunk.
	newest int

	// oldest is the index of the oldest chunk.
	oldest int

	// queries is a circular buffer of chunks. Each chunk is a map of
	// dnsReqKey -> timestamp.
	queries []map[dnsQueryKey]uint64
}

// NewDNSQueriesDataBase creates a new dnsQueriesDataBase with the given
// capacity and number of chunks. The capacity must be a multiple of chunks.
func NewDNSQueriesDataBase(capacity int, chunks int) (*dnsQueriesDataBase, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("capacity must be greater than 0")
	}
	if chunks < 2 {
		return nil, fmt.Errorf("chunks must be greater than 2")
	}
	if capacity%chunks != 0 {
		return nil, fmt.Errorf("capacity must be a multiple of chunks")
	}

	queries := make([]map[dnsQueryKey]uint64, chunks)
	queries[0] = make(map[dnsQueryKey]uint64)

	return &dnsQueriesDataBase{
		chunkCap: capacity / chunks,
		chunks:   chunks,
		newest:   0,
		oldest:   0,
		queries:  queries,
	}, nil
}

// Store stores the given timestamp for the given key. If the current (newest)
// chunk is full, a new chunk is created. If the circular buffer of chunks is
// full, the oldest chunk is replaced by a new one. The key is not stored if it
// already exists in another chunk.
func (db *dnsQueriesDataBase) Store(key dnsQueryKey, value uint64) error {
	log.Debugf("store %v -> %d (oldest %d, newest %d, len(newest) %d, chunkCap %d)",
		key, value, db.oldest, db.newest, len(db.queries[db.newest]), db.chunkCap)

	// Avoid overwriting a key or adding it twice as it could already exist in
	// another chunk. This should not happen as the DNSQueryKey is supposed to
	// be unique.
	_, err := db.load(key)
	if err == nil {
		log.Debugf("key %v already exists", key)
		return fmt.Errorf("key %v already exists", key)
	}

	db.Lock()
	defer db.Unlock()

	newestChunk := db.queries[db.newest]
	if len(newestChunk) == db.chunkCap {
		newest := (db.newest + 1) % db.chunks
		log.Debugf("update newest chunk %d -> %d", db.newest, newest)
		db.newest = newest

		// Create a new chunk even if it replaces the oldest one.
		db.queries[db.newest] = make(map[dnsQueryKey]uint64)
		newestChunk = db.queries[db.newest]

		// Update the oldest chunk if it was replaced.
		if db.newest == db.oldest {
			oldest := (db.oldest + 1) % db.chunks
			log.Debugf("update oldest chunk %d -> %d", db.oldest, oldest)
			db.oldest = oldest
		}
	}

	newestChunk[key] = value
	log.Debugf("stored %v -> %d in chunk %d (oldest %d, newest %d, len(newest) %d)",
		key, value, db.newest, db.oldest, db.newest, len(db.queries[db.newest]))

	return nil
}

// load loads the timestamp for the given key. It returns an error if the key
// is not found. The search is performed from oldest to newest as the key is
// more likely to be found in the oldest chunk.
func (db *dnsQueriesDataBase) load(key dnsQueryKey) (uint64, error) {
	db.Lock()
	defer db.Unlock()

	log.Debugf("load %v (oldest %d, newest %d, len(oldest) %d)",
		key, db.oldest, db.newest, len(db.queries[db.oldest]))

	// Search from oldest to newest as the key is more likely to be found in
	// the oldest chunk.
	index := db.oldest
	for {
		chunk := db.queries[index]
		if ret, ok := chunk[key]; ok {
			log.Debugf("loaded key %v from chunk %d", key, index)
			return ret, nil
		}

		if index == db.newest {
			break
		}

		index = (index + 1) % db.chunks
	}

	return 0, fmt.Errorf("key %v not found", key)
}

// LoadAndDelete loads the timestamp for the given key and deletes it. If the
// key is not found, an error is returned. The search starts from the oldest
// chunk and stops when the newest chunk is reached.
func (db *dnsQueriesDataBase) LoadAndDelete(key dnsQueryKey) (uint64, error) {
	db.Lock()
	defer db.Unlock()

	log.Debugf("load and delete %v (oldest %d, newest %d, len(oldest) %d)",
		key, db.oldest, db.newest, len(db.queries[db.oldest]))

	// Search from oldest to newest as the key is more likely to be found in
	// the oldest chunk.
	index := db.oldest
	for {
		log.Debugf("search key %v in chunk %d", key, index)

		chunk := db.queries[index]
		if ret, ok := chunk[key]; ok {
			log.Debugf("found key %v in chunk %d", key, index)

			delete(chunk, key)

			// Update the oldest chunk if it was emptied.
			if len(chunk) == 0 {
				oldest := (db.oldest + 1) % db.chunks
				log.Debugf("update oldest chunk %d -> %d", db.oldest, oldest)
				db.oldest = oldest
			}

			log.Debugf("loaded and deleted %v -> %d from chunk %d (oldest %d, newest %d, len(oldest) %d)",
				key, ret, index, db.oldest, db.newest, len(db.queries[db.oldest]))

			return ret, nil
		}

		// Stop when the newest chunk is reached.
		if index == db.newest {
			return 0, fmt.Errorf("key %q not found", key)
		}

		index = (index + 1) % db.chunks
	}
}

// len returns the number of elements in the database, meaning the sum of the
// lengths of all chunks. It is intended to be used for debugging purposes.
func (db *dnsQueriesDataBase) len() int {
	db.Lock()
	defer db.Unlock()

	index := db.oldest
	totalLen := 0
	for {
		len := len(db.queries[index])
		log.Debugf("add len %d from chunk %d", len, index)
		totalLen += len

		// Stop when the newest chunk is reached.
		if index == db.newest {
			break
		}

		index = (index + 1) % db.chunks
	}

	log.Debugf("total len %d", totalLen)

	return totalLen
}

// string returns a string representation of the database, meaning the
// concatenation of the string representations of all chunks. It is intended to
// be used for debugging purposes.
func (db *dnsQueriesDataBase) string() string {
	db.Lock()
	defer db.Unlock()

	index := db.oldest
	ret := "db:\n"
	for {
		ret += fmt.Sprintf("chunk %d (len %d): %v\n", index, len(db.queries[index]), db.queries[index])

		// Stop when the newest chunk is reached.
		if index == db.newest {
			break
		}

		index = (index + 1) % db.chunks
	}

	return ret
}

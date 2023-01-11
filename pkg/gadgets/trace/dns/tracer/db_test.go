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

import "testing"

func assertLen(t *testing.T, db *dnsQueriesDataBase, expected int) {
	t.Helper()

	n := db.len()
	if n != expected {
		t.Fatalf("Expected %d queries in database, but got %d\n%s", expected, n, db.string())
	}
}

func assertValue(t *testing.T, db *dnsQueriesDataBase, actual uint64, expected uint64) {
	t.Helper()

	if actual != expected {
		t.Fatalf("Expected value %d, but got %d\n%s", actual, expected, db.string())
	}
}

func assertNoErrorWhileCreating(t *testing.T, err error, cap int, chunks int) {
	t.Helper()

	if err != nil {
		t.Fatalf("Unexpected error when creating database with capacity %d and chunks %d: %v",
			cap, chunks, err)
	}
}

func assertErrorWhileCreating(t *testing.T, err error, cap int, chunks int) {
	t.Helper()

	if err == nil {
		t.Fatalf("Expected error when creating database with capacity %d and chunks %d", cap, chunks)
	}
}

func assertNoErrorWhileStoring(t *testing.T, db *dnsQueriesDataBase, err error, key dnsQueryKey) {
	t.Helper()

	if err != nil {
		t.Fatalf("Unexpected error when storing key %v\n%s", key, db.string())
	}
}

func assertErrorWhileStoring(t *testing.T, db *dnsQueriesDataBase, err error, key dnsQueryKey) {
	t.Helper()

	if err == nil {
		t.Fatalf("Expected error when storing key %v\n%s", key, db.string())
	}
}

func assertNoErrorWhileLoadingAndDeleting(t *testing.T, db *dnsQueriesDataBase, err error, key dnsQueryKey) {
	t.Helper()

	if err != nil {
		t.Fatalf("Unexpected error when loading and deleting key %v: %v\n%s", key, err, db.string())
	}
}

func assertErrorWhileLoadingAndDeleting(t *testing.T, db *dnsQueriesDataBase, err error, key dnsQueryKey) {
	t.Helper()

	if err == nil {
		t.Fatalf("Expected error when loading and deleting key %v\n%s", key, db.string())
	}
}

func assertNoErrorWhileLoading(t *testing.T, db *dnsQueriesDataBase, err error, key dnsQueryKey) {
	t.Helper()

	if err != nil {
		t.Fatalf("Unexpected error when loading %v: %v\n%s", key, err, db.string())
	}
}

func TestNewDNSQueriesDataBase(t *testing.T) {
	var cap int
	var chunks int

	// Error cases
	// Capacity must be greater than 0
	cap = 0
	chunks = 2
	_, err := NewDNSQueriesDataBase(cap, chunks)
	assertErrorWhileCreating(t, err, cap, chunks)

	// Chunks must be greater or equal than 2
	cap = 1
	chunks = 0
	_, err = NewDNSQueriesDataBase(cap, chunks)
	assertErrorWhileCreating(t, err, cap, chunks)

	// Chunks must be multiple of capacity
	cap = 3
	chunks = 2
	_, err = NewDNSQueriesDataBase(cap, chunks)
	assertErrorWhileCreating(t, err, cap, chunks)

	// Success cases
	cap = 4
	chunks = 2
	_, err = NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)
}

func TestDNSQueriesDataBaseStore(t *testing.T) {
	cap := 2
	chunks := 2
	db, err := NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)

	// Error cases
	key1 := dnsQueryKey{id: 1, addr: [16]byte{1}}
	val1 := uint64(1)
	err = db.Store(key1, val1)
	assertNoErrorWhileStoring(t, db, err, key1)
	assertLen(t, db, 1)

	err = db.Store(key1, val1)
	assertErrorWhileStoring(t, db, err, key1)
	assertLen(t, db, 1)

	// Success cases
	key2 := dnsQueryKey{id: 2, addr: [16]byte{2}}
	val2 := uint64(2)
	err = db.Store(key2, val2)
	assertNoErrorWhileStoring(t, db, err, key2)
	assertLen(t, db, 2)
}

func TestDNSQueriesDataBaseLoad(t *testing.T) {
	cap := 2
	chunks := 2
	db, err := NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)

	// Error cases
	key1 := dnsQueryKey{id: 1, addr: [16]byte{1}}
	_, err = db.load(key1)
	assertErrorWhileLoadingAndDeleting(t, db, err, key1)

	// Success cases
	key2 := dnsQueryKey{id: 2, addr: [16]byte{2}}
	val2 := uint64(2)
	err = db.Store(key2, val2)
	assertNoErrorWhileStoring(t, db, err, key2)
	assertLen(t, db, 1)

	ret, err := db.load(key2)
	assertNoErrorWhileLoading(t, db, err, key2)
	assertValue(t, db, ret, val2)
	assertLen(t, db, 1)
}

func TestDNSQueriesDataBaseLoadAndDelete(t *testing.T) {
	cap := 2
	chunks := 2
	db, err := NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)

	// Error cases
	key1 := dnsQueryKey{id: 1, addr: [16]byte{1}}
	_, err = db.LoadAndDelete(key1)
	assertErrorWhileLoadingAndDeleting(t, db, err, key1)

	// Success cases
	key2 := dnsQueryKey{id: 2, addr: [16]byte{2}}
	val2 := uint64(2)
	err = db.Store(key2, val2)
	assertNoErrorWhileStoring(t, db, err, key2)
	assertLen(t, db, 1)

	ret, err := db.LoadAndDelete(key2)
	assertNoErrorWhileLoadingAndDeleting(t, db, err, key2)
	assertValue(t, db, ret, val2)
	assertLen(t, db, 0)
}

func TestOverwriteOldest(t *testing.T) {
	cap := 4
	var chunks int
	dbs := []*dnsQueriesDataBase{}

	chunks = 2
	db, err := NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)
	dbs = append(dbs, db)

	chunks = 4
	db, err = NewDNSQueriesDataBase(cap, chunks)
	assertNoErrorWhileCreating(t, err, cap, chunks)
	dbs = append(dbs, db)

	for _, db := range dbs {
		t.Logf("Testing database with capacity %d and chunks %d", cap, db.chunks)

		// Store 4 keys
		key1 := dnsQueryKey{id: 1, addr: [16]byte{1}}
		val1 := uint64(1)
		err := db.Store(key1, val1)
		assertNoErrorWhileStoring(t, db, err, key1)
		assertLen(t, db, 1)

		key2 := dnsQueryKey{id: 2, addr: [16]byte{2}}
		val2 := uint64(2)
		err = db.Store(key2, val2)
		assertNoErrorWhileStoring(t, db, err, key2)
		assertLen(t, db, 2)

		key3 := dnsQueryKey{id: 3, addr: [16]byte{3}}
		val3 := uint64(3)
		err = db.Store(key3, val3)
		assertNoErrorWhileStoring(t, db, err, key3)
		assertLen(t, db, 3)

		key4 := dnsQueryKey{id: 4, addr: [16]byte{4}}
		val4 := uint64(4)
		err = db.Store(key4, val4)
		assertNoErrorWhileStoring(t, db, err, key4)
		assertLen(t, db, 4)

		// Store a fifth key, which should overwrite the oldest key
		key5 := dnsQueryKey{id: 5, addr: [16]byte{5}}
		val5 := uint64(5)
		err = db.Store(key5, val5)
		assertNoErrorWhileStoring(t, db, err, key5)
		if db.chunks == 2 {
			// With 2 chunks of 2 entries, the overwrite operation should have
			// evicted 2 entries, so the database should have 3 entries (the two
			// remaining chunks plus the new one).
			assertLen(t, db, 3)

			// Try to load the keys that should have been overwritten
			ret, err := db.LoadAndDelete(key1)
			assertErrorWhileLoadingAndDeleting(t, db, err, key1)
			assertValue(t, db, ret, 0)

			ret, err = db.LoadAndDelete(key2)
			assertErrorWhileLoadingAndDeleting(t, db, err, key2)
			assertValue(t, db, ret, 0)
		} else {
			// With 4 chunks of 1 entry, it is like having a circular buffer of
			// 4 entries, so the database should have 4 entries.
			assertLen(t, db, 4)

			// Try to load the key that should have been overwritten
			ret, err := db.LoadAndDelete(key1)
			assertErrorWhileLoadingAndDeleting(t, db, err, key1)
			assertValue(t, db, ret, 0)
		}

		// Try to store a sixth key
		key6 := dnsQueryKey{id: 6, addr: [16]byte{6}}
		val6 := uint64(6)
		err = db.Store(key6, val6)
		assertNoErrorWhileStoring(t, db, err, key6)
		// Regardless the number of chunks, the new database should have 4
		// entries. However, in the case of 4 chucks there was a overwrite
		// operation before adding the new one. While for 2 chunks there wasn't
		// an overwrite operation before adding the new one.
		assertLen(t, db, 4)

		// Try to load the key that should have been overwritten again
		ret, err := db.LoadAndDelete(key2)
		assertErrorWhileLoadingAndDeleting(t, db, err, key2)
		assertValue(t, db, ret, 0)
		assertLen(t, db, 4)

		// Load and delete the key that should not have been overwritten
		ret, err = db.LoadAndDelete(key3)
		assertNoErrorWhileLoadingAndDeleting(t, db, err, key3)
		assertValue(t, db, ret, val3)
		assertLen(t, db, 3)

		ret, err = db.LoadAndDelete(key4)
		assertNoErrorWhileLoadingAndDeleting(t, db, err, key4)
		assertValue(t, db, ret, val4)
		assertLen(t, db, 2)

		ret, err = db.LoadAndDelete(key5)
		assertNoErrorWhileLoadingAndDeleting(t, db, err, key5)
		assertValue(t, db, ret, val5)
		assertLen(t, db, 1)

		ret, err = db.LoadAndDelete(key6)
		assertNoErrorWhileLoadingAndDeleting(t, db, err, key6)
		assertValue(t, db, ret, val6)
		assertLen(t, db, 0)
	}
}

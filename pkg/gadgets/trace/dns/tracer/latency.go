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
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	dnsLatencyMaxMapSize int = 1024
)

// dnsLatencyCalculator calculates the latency between a request and its response.
// It tracks up to dnsLatencyMaxMapSize*2 outstanding requests; if more arrive, older ones will be dropped to make space.
// All operations are thread-safe.
type dnsLatencyCalculator struct {
	db *dnsQueriesDataBase
}

func newDNSLatencyCalculator() *dnsLatencyCalculator {
	db, err := NewDNSQueriesDataBase(dnsLatencyMaxMapSize*2, 2)
	if err != nil {
		panic("TODO: Manage this, return an error?")
	}

	return &dnsLatencyCalculator{
		db: db,
	}
}

func (c *dnsLatencyCalculator) storeDNSRequestTimestamp(saddr [16]uint8, id uint16, timestamp uint64) {
	// Store the timestamp of the request so we can calculate the latency once
	// the response arrives.
	err := c.db.Store(dnsQueryKey{saddr, id}, timestamp)
	if err != nil {
		// Should never happen!
		panic("TODO: What to do here?")
	}
}

// If there is no corresponding DNS request (either never received or evicted to make space), then this returns zero.
func (c *dnsLatencyCalculator) calculateDNSResponseLatency(daddr [16]uint8, id uint16, timestamp uint64) time.Duration {
	// Lookup the request timestamp so we can subtract it from the response timestamp.
	reqTS, err := c.db.LoadAndDelete(dnsQueryKey{daddr, id})
	if err != nil {
		// Either an invalid ID or we evicted the request from the map to free
		// space.
		log.Errorf("Failed to calculate DNS latency: %v", err)
		return 0
	}

	if reqTS > timestamp {
		// Should never happen assuming timestamps are monotonic, but handle it just in case.
		return 0
	}

	return time.Duration(timestamp - reqTS)
}

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
	"sync"
	"time"
)

const (
	dnsLatencyMaxMapSize      int    = 1024
	dnsReqTSMapRotateInterval uint64 = 5_000_000_000 // 5e+9 ns = 5 seconds
)

// dnsReqKey is a unique identifier for a DNS request.
// The address is the request's source IP address (equals destination address of the response).
// The ID comes from the DNS header.
type dnsReqKey struct {
	addr [16]uint8 // Either IPv4 or IPv6.
	id   uint16
}

// dnsLatencyCalculator calculates the latency between a request and its response.
// It tracks up to dnsLatencyMaxMapSize*2 outstanding requests; if more arrive, older ones will be dropped to make space.
// All operations are thread-safe.
type dnsLatencyCalculator struct {
	sync.Mutex      // Protects currentReqTSMap and prevReqTSMap.
	currentReqTSMap map[dnsReqKey]uint64
	prevReqTSMap    map[dnsReqKey]uint64
}

func newDNSLatencyCalculator() *dnsLatencyCalculator {
	return &dnsLatencyCalculator{
		currentReqTSMap: make(map[dnsReqKey]uint64),
		prevReqTSMap:    make(map[dnsReqKey]uint64),
	}
}

func (c *dnsLatencyCalculator) storeDNSRequestTimestamp(saddr [16]uint8, id uint16, timestamp uint64) {
	c.Lock()
	defer c.Unlock()

	// If the current map is full, drop the previous map and allocate a new one to make space.
	if len(c.currentReqTSMap) == dnsLatencyMaxMapSize {
		c.prevReqTSMap = c.currentReqTSMap
		c.currentReqTSMap = make(map[dnsReqKey]uint64)
	}

	// Store the timestamp of the request so we can calculate the latency once the response arrives.
	key := dnsReqKey{saddr, id}
	c.currentReqTSMap[key] = timestamp
}

// If there is no corresponding DNS request (either never received or evicted to make space), then this returns zero.
func (c *dnsLatencyCalculator) calculateDNSResponseLatency(daddr [16]uint8, id uint16, timestamp uint64) time.Duration {
	c.Lock()
	defer c.Unlock()

	// Lookup the request timestamp so we can subtract it from the response timestamp.
	key := dnsReqKey{daddr, id}
	reqTS, ok := c.currentReqTSMap[key]
	if ok {
		// Found the request in the current map, so delete the entry to free space.
		delete(c.currentReqTSMap, key)
	} else {
		reqTS, ok = c.prevReqTSMap[key]
		if ok {
			delete(c.prevReqTSMap, key)
		} else {
			// Either an invalid ID or we evicted the request from the map to free space.
			return 0
		}
	}

	if reqTS > timestamp {
		// Should never happen assuming timestamps are monotonic, but handle it just in case.
		return 0
	}

	return time.Duration(timestamp - reqTS)
}

func (c *dnsLatencyCalculator) numOutstandingRequests() int {
	c.Lock()
	defer c.Unlock()

	return len(c.currentReqTSMap) + len(c.prevReqTSMap)
}

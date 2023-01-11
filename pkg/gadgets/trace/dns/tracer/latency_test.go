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
	"testing"
	"time"
)

func assertLatency(t *testing.T, actual time.Duration, expected time.Duration) {
	if actual != expected {
		t.Fatalf("Expected latency %d but got %d", expected, actual)
	}
}

func assertNoLatency(t *testing.T, actual time.Duration) {
	if actual != 0 {
		t.Fatalf("Expected no latency returned, but got %d", actual)
	}
}

func TestDnsLatencyCalculatorRequestResponse(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDNSLatencyCalculator()

	c.storeDNSRequestTimestamp(addr, id, 100)

	latency := c.calculateDNSResponseLatency(addr, id, 500)
	assertLatency(t, latency, 400*time.Nanosecond)
}

func TestDnsLatencyCalculatorResponseWithoutMatchingRequest(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDNSLatencyCalculator()

	// Response for an addr/id without a corresponding request.
	latency := c.calculateDNSResponseLatency(addr, id, 500)
	assertNoLatency(t, latency)
}

func TestDnsLatencyCalculatorResponseWithSameIdButDifferentSrcIP(t *testing.T) {
	firstAddr, secondAddr := [16]uint8{1}, [16]uint8{2}
	id := uint16(1)
	c := newDNSLatencyCalculator()

	// Two requests, same ID, different IPs
	c.storeDNSRequestTimestamp(firstAddr, id, 100)
	c.storeDNSRequestTimestamp(secondAddr, id, 200)

	// Latency calculated correctly for both responses.
	firstLatency := c.calculateDNSResponseLatency(firstAddr, id, 500)
	assertLatency(t, firstLatency, 400*time.Nanosecond)
	secondLatency := c.calculateDNSResponseLatency(secondAddr, id, 700)
	assertLatency(t, secondLatency, 500*time.Nanosecond)
}

func TestDnsLatencyCalculatorManyOutstandingRequests(t *testing.T) {
	addr := [16]uint8{1}
	c := newDNSLatencyCalculator()

	var lastID uint16
	for i := 0; i < dnsLatencyMaxMapSize*3; i++ {
		id := uint16(i)
		c.storeDNSRequestTimestamp(addr, id, 100)
		lastID = id
	}

	// Response to most recent request should report latency.
	latency := c.calculateDNSResponseLatency(addr, lastID, 300)
	assertLatency(t, latency, 200*time.Nanosecond)

	// Response to first (dropped) requests should NOT report latency.
	latency = c.calculateDNSResponseLatency(addr, 0, 400)
	assertNoLatency(t, latency)

	// Response to prior request that wasn't yet dropped should report latency.
	latency = c.calculateDNSResponseLatency(addr, lastID-uint16(dnsLatencyMaxMapSize)-1, 600)
	assertLatency(t, latency, 500*time.Nanosecond)
}

func TestDnsLatencyCalculatorResponseWithZeroTimestamp(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDNSLatencyCalculator()

	c.storeDNSRequestTimestamp(addr, id, 100)

	// Response has timestamp zero (should never happen, but check it anyway to prevent overflow).
	latency := c.calculateDNSResponseLatency(addr, id, 0)
	assertNoLatency(t, latency)
}

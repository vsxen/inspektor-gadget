// Copyright 2023 The Inspektor Gadget authors
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

package tcpbits

import (
	"fmt"
	"strings"
)

// Names of the TCP states without the TCP_ prefix
// from https://github.com/torvalds/linux/blob/v6.2/include/net/tcp_states.h#L12-L27
var tcpstates = map[uint8]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

// TCPState converts the state of a TCP connection to its name without the TCP_ prefix
func TCPState(tcpstate uint8) string {
	if ret, ok := tcpstates[tcpstate]; ok {
		return ret
	}
	return fmt.Sprintf("UNKNOWN#%d", tcpstate)
}

// from https://github.com/torvalds/linux/blob/v6.2/include/net/tcp.h#L840-L847
const (
	tcphdrFin = 0x01
	tcphdrSyn = 0x02
	tcphdrRst = 0x04
	tcphdrPsh = 0x08
	tcphdrAck = 0x10
	tcphdrUrg = 0x20
	tcphdrEce = 0x40
	tcphdrCwr = 0x80
)

// TCPFlags converts the flags of a TCP packet to a string
func TCPFlags(flags uint8) string {
	arr := []string{}
	if flags&tcphdrFin != 0 {
		arr = append(arr, "FIN")
	}
	if flags&tcphdrSyn != 0 {
		arr = append(arr, "SYN")
	}
	if flags&tcphdrRst != 0 {
		arr = append(arr, "RST")
	}
	if flags&tcphdrPsh != 0 {
		arr = append(arr, "PSH")
	}
	if flags&tcphdrAck != 0 {
		arr = append(arr, "ACK")
	}
	if flags&tcphdrUrg != 0 {
		arr = append(arr, "URG")
	}
	if flags&tcphdrEce != 0 {
		arr = append(arr, "ECE")
	}
	if flags&tcphdrCwr != 0 {
		arr = append(arr, "CWR")
	}
	return strings.Join(arr, "|")
}

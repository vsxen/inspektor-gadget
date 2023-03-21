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

package tracer

import (
	"strings"
	"testing"

	"github.com/moby/moby/pkg/parsers/kernel"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

func TestDropReasons(t *testing.T) {
	utilstest.RequireRoot(t)

	// The tracepoint was added in 5.17
	utilstest.RequireKernelVersion(t, &kernel.VersionInfo{Kernel: 5, Major: 17, Minor: 0})

	// Do not test all values: they can change between kernel versions.
	// Just test that a few values looks ok.

	str := lookupDropReason(5)
	if strings.HasPrefix(str, "UNKNOWN") || str == "" {
		t.Fatalf("Unexpected drop reason: %q", str)
	}
	if len(dropReasons) < 10 {
		t.Fatalf("Too few drop reasons: %d", len(dropReasons))
	}
}

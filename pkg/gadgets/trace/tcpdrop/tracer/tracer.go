// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdrop/tracer/tcpbits"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdrop/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -no-global-types -type event tcpdrop ./bpf/tcpdrop.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct{}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs tcpdropObjects

	kfreeSkbLink link.Link

	reader *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

func (t *Tracer) close() {
	t.kfreeSkbLink = gadgets.CloseLink(t.kfreeSkbLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadTcpdrop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	opts := ebpf.CollectionOptions{}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.kfreeSkbLink, err = link.Tracepoint("skb", "kfree_skb", t.objs.IgTcpdrop, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint kfree_skb: %w", err)
	}

	reader, err := perf.NewReader(t.objs.tcpdropMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}
	t.reader = reader

	return nil
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*tcpdropEvent)(unsafe.Pointer(&record.RawSample[0]))

		reason := lookupDropReason(int(bpfEvent.Reason))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:           bpfEvent.Pid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Dport:         gadgets.Htons(bpfEvent.Dport),
			Sport:         gadgets.Htons(bpfEvent.Sport),
			State:         tcpbits.TCPState(bpfEvent.State),
			Tcpflags:      tcpbits.TCPFlags(bpfEvent.Tcpflags),
			Reason:        reason,
		}

		if bpfEvent.Af == unix.AF_INET {
			event.IPVersion = 4
		} else if bpfEvent.Af == unix.AF_INET6 {
			event.IPVersion = 6
		}

		event.Saddr = gadgets.IPStringFromBytes(bpfEvent.Saddr, event.IPVersion)
		event.Daddr = gadgets.IPStringFromBytes(bpfEvent.Daddr, event.IPVersion)

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

var (
	btfDetectDropReason sync.Once
	dropReasons         = map[int]string{}
	dropReasonsErr      error
)

func lookupDropReason(reason int) string {
	btfDetectDropReason.Do(func() {
		btfSpec, err := btf.LoadKernelSpec()
		if err != nil {
			dropReasonsErr = err
			return
		}

		enum := &btf.Enum{}
		err = btfSpec.TypeByName("skb_drop_reason", &enum)
		if err != nil {
			dropReasonsErr = err
			return
		}
		for _, v := range enum.Values {
			str := v.Name
			str = strings.TrimPrefix(str, "SKB_DROP_REASON_")
			str = strings.TrimPrefix(str, "SKB_")

			dropReasons[int(v.Value)] = str
		}
	})

	if dropReasonsErr != nil {
		return dropReasonsErr.Error()
	}
	if ret, ok := dropReasons[reason]; ok {
		return ret
	}
	return fmt.Sprintf("UNKNOWN#%d", reason)
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	// tcpdrop does not filter by container but we need to implement
	// MountNsMapSetter, otherwise LocalManager.CanOperateOn() returns false
	// and events won't be enriched.
	// TODO: find a way to enable enrichers without setting up an empty
	//       SetMountNsMap().
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

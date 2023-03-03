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

package grpcruntime

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	GadgetServiceSocket = "/run/gadgetservice.socket"

	ParamNode             = "node"
	ParamConnectionMethod = "connection-method"

	// ResultTimeout is the time in seconds we wait for a result to return from the gadget
	// after sending a Stop command
	ResultTimeout = 30
)

type Runtime struct {
	catalog *runtime.Catalog
}

// New instantiates the runtime and loads the locally stored gadget catalog. If no catalog is stored locally,
// it will try to fetch one from one of the gadget nodes and store it locally. It will issue warnings on
// failures.
func New() *Runtime {
	r := &Runtime{}

	// Initialize Catalog
	catalog, err := loadLocalGadgetCatalog()
	if err == nil {
		r.catalog = catalog
		return r
	}

	catalog, err = loadRemoteGadgetCatalog()
	if err != nil {
		log.Warnf("could not load gadget catalog from remote: %v", err)
		return r
	}
	r.catalog = catalog

	err = storeCatalog(catalog)
	if err != nil {
		log.Warnf("could not store gadget catalog: %v", err)
	}

	return r
}

func (r *Runtime) UpdateCatalog() error {
	catalog, err := loadRemoteGadgetCatalog()
	if err != nil {
		return fmt.Errorf("loading remote gadget catalog: %w", err)
	}

	return storeCatalog(catalog)
}

func (r *Runtime) Init(runtimeGlobalParams *params.Params) error {
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamNode,
			Description: "Comma-separated list of nodes to run the gadget on",
		},
	}
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:            ParamConnectionMethod,
			Description:    "Method that should be used to connect to the Inspektor Gadget nodes",
			PossibleValues: []string{"kubeapi-server-per-node", "grpc-direct"},
			DefaultValue:   "kubeapi-server-per-node",
		},
	}
}

type gadgetPod struct {
	name string
	node string
}

func getGadgetPods(ctx context.Context, nodes []string) ([]gadgetPod, error) {
	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to creating RESTConfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to set up trace client: %w", err)
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods("gadget").List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("getting pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no gadget pods found. Is Inspektor Gadget deployed?")
	}

	if len(nodes) == 0 {
		res := make([]gadgetPod, 0, len(pods.Items))

		for _, pod := range pods.Items {
			res = append(res, gadgetPod{name: pod.Name, node: pod.Spec.NodeName})
		}

		return res, nil
	}

	// Remove possible duplicates in nodes
	resMap := map[string]string{}
	for _, node := range nodes {
		resMap[node] = ""
	}

	// Filter nodes
	for node := range resMap {
		for _, pod := range pods.Items {
			if node == pod.Spec.NodeName {
				resMap[node] = pod.Name
				break
			}
		}
	}

	res := make([]gadgetPod, 0, len(nodes))
	for node, pod := range resMap {
		if pod == "" {
			log.Warnf("node %q not found or without gadget pod", node)
			continue
		}
		res = append(res, gadgetPod{name: pod, node: node})
	}

	return res, nil
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (map[string][]byte, error) {
	// Get nodes to run on
	nodes := gadgetCtx.RuntimeParams().Get(ParamNode).AsStringSlice()
	pods, err := getGadgetPods(gadgetCtx.Context(), nodes)
	if err != nil {
		return nil, fmt.Errorf("get gadget pods: %w", err)
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods correspond to following node(s): %v", nodes)
	}

	if gadgetCtx.GadgetDesc().Type() == gadgets.TypeTraceIntervals {
		gadgetCtx.Parser().EnableSnapshots(
			gadgetCtx.Context(),
			time.Duration(gadgetCtx.GadgetParams().Get(gadgets.ParamInterval).AsInt32())*time.Second,
			2,
		)
	}

	results := make(map[string][]byte)
	var resultsLock sync.Mutex

	wg := sync.WaitGroup{}
	for _, pod := range pods {
		wg.Add(1)
		go func(pod gadgetPod) {
			gadgetCtx.Logger().Debugf("running gadget on node %q", pod.node)
			res, err := r.runGadget(gadgetCtx, pod)
			if err != nil {
				gadgetCtx.Logger().Errorf("node %q: %w", pod.node, err)
			}
			if res != nil {
				resultsLock.Lock()
				results[pod.node] = res
				resultsLock.Unlock()
			}
			wg.Done()
		}(pod)
	}

	wg.Wait()
	return results, nil
}

func (r *Runtime) runGadget(gadgetCtx runtime.GadgetContext, pod gadgetPod) ([]byte, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialOpt := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return NewK8SExecConn(ctx, pod, time.Second*30)
		// return NewK8SPortForwardConn(ctx, s, time.Second*30)
	})

	conn, err := grpc.DialContext(ctx, "", dialOpt, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("could not dial gadget pod on node %q: %w", pod.node, err)
	}
	defer conn.Close()
	client := pb.NewGadgetManagerClient(conn)

	allParams := make(map[string]string)
	gadgetCtx.GadgetParams().CopyToMap(allParams, "")
	gadgetCtx.OperatorsParamCollection().CopyToMap(allParams, "operator.")

	runRequest := &pb.GadgetRunRequest{
		GadgetName:     gadgetCtx.GadgetDesc().Name(),
		GadgetCategory: gadgetCtx.GadgetDesc().Category(),
		Params:         allParams,
		Nodes:          nil,
		FanOut:         false,
		LogLevel:       uint32(gadgetCtx.Logger().GetLevel()),
		Timeout:        int64(gadgetCtx.Timeout()),
	}

	runClient, err := client.RunGadget(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	controlRequest := &pb.GadgetControlRequest{Event: &pb.GadgetControlRequest_RunRequest{RunRequest: runRequest}}
	err = runClient.Send(controlRequest)
	if err != nil {
		return nil, err
	}

	parser := gadgetCtx.Parser()

	jsonHandler := func([]byte) {}
	jsonArrayHandler := func([]byte) {}

	if parser != nil {
		jsonHandler = parser.JSONHandlerFunc()
		jsonArrayHandler = parser.JSONHandlerFuncArray(pod.node)
	}

	doneChan := make(chan bool)

	var result []byte
	expectedSeq := uint32(1)

	go func() {
		for {
			ev, err := runClient.Recv()
			if err != nil {
				break
			}
			switch ev.Type {
			case pb.EventTypeGadgetPayload:
				if expectedSeq != ev.Seq {
					gadgetCtx.Logger().Warnf("%-20s | expected seq %d, got %d, %d messages dropped", pod.node, expectedSeq, ev.Seq, ev.Seq-expectedSeq)
				}
				expectedSeq = ev.Seq + 1
				if len(ev.Payload) > 0 && ev.Payload[0] == '[' {
					jsonArrayHandler(ev.Payload)
					continue
				}
				jsonHandler(ev.Payload)
			case pb.EventTypeGadgetResult:
				result = ev.Payload
			case pb.EventTypeGadgetJobID:
			// not needed right now
			case pb.EventTypeGadgetDone:
				gadgetCtx.Logger().Debug("got EventTypeGadgetDone from server")
				doneChan <- true
				return
			default:
				if ev.Type >= 1<<pb.EventLogShift {
					gadgetCtx.Logger().Log(logger.Level(ev.Type>>pb.EventLogShift), fmt.Sprintf("%-20s | %s", pod.node, string(ev.Payload)))
					continue
				}
				gadgetCtx.Logger().Warnf("unknown payload type %d: %s", ev.Type, ev.Payload)
			}
		}
		doneChan <- true
	}()

	select {
	case <-doneChan:
		gadgetCtx.Logger().Debug("done from server side")
	case <-gadgetCtx.Context().Done():
		// Send stop request
		controlRequest := &pb.GadgetControlRequest{Event: &pb.GadgetControlRequest_StopRequest{StopRequest: &pb.GadgetStopRequest{}}}
		runClient.Send(controlRequest)

		// Wait for done or timeout
		select {
		case <-doneChan:
			gadgetCtx.Logger().Debug("done after cancel request")
		case <-time.After(ResultTimeout * time.Second):
			return nil, fmt.Errorf("timed out while getting result")
		}
	}
	return result, nil
}

func (r *Runtime) GetCatalog() (*runtime.Catalog, error) {
	return r.catalog, nil
}

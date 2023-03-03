// Copyright 2022-2023 The Inspektor Gadget authors
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

package runtime

import (
	"context"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetContext interface {
	ID() string
	Parser() parser.Parser
	GadgetDesc() gadgets.GadgetDesc
	Context() context.Context
	Operators() operators.Operators
	Logger() logger.Logger
	RuntimeParams() *params.Params
	GadgetParams() *params.Params
	OperatorsParamCollection() params.Collection
	Timeout() time.Duration
}

// Runtime is the interface for gadget runtimes. Runtimes are used to control the lifecycle of gadgets either locally
// or remotely.
type Runtime interface {
	Init(globalRuntimeParams *params.Params) error
	Close() error
	GlobalParamDescs() params.ParamDescs
	ParamDescs() params.ParamDescs
	RunGadget(gadgetCtx GadgetContext) ([]byte, error)
}

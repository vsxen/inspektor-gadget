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

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
)

// common params for all gadgets
var params utils.CommonFlags

var rootCmd = &cobra.Command{
	Use:   "kubectl-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
}

func init() {
	utils.FlagInit(rootCmd)
}

func main() {
	runtime := grpcruntime.New()

	// columnFilters for kubectl-gadget
	columnFilters := []columns.ColumnFilter{columns.Or(columns.WithTag("kubernetes"), columns.WithNoTags())}
	common.AddCommandsFromRegistry(rootCmd, runtime, columnFilters)

	// Advise category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd())

	rootCmd.AddCommand(&cobra.Command{
		Use:   "update-catalog",
		Short: "Download a new gadget catalog from the nodes to have it in sync with this client",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runtime.UpdateCatalog()
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Kubernetes
}

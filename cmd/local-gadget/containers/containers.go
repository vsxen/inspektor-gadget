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

package containers

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

type ContainerFlags struct {
	noTrunc bool
}

func NewListContainersCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var containerFlags ContainerFlags

	cmd := &cobra.Command{
		Use:   "list-containers",
		Short: "List all containers",
		RunE: func(*cobra.Command, []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return commonutils.WrapInErrManagerInit(err)
			}
			defer localGadgetManager.Close()

			parser, err := newContainerParser(&commonFlags.OutputConfig, &containerFlags)
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}

			containers := localGadgetManager.GetContainersBySelector(&containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			})

			parser.Sort(containers, []string{"runtime", "name"})

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.MarshalIndent(containers, "", "  ")
				if err != nil {
					return commonutils.WrapInErrMarshalOutput(err)
				}

				fmt.Printf("%s\n", b)
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoTable(containers))
			default:
				return commonutils.WrapInErrOutputModeNotSupported(commonFlags.OutputMode)
			}

			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(
		&containerFlags.noTrunc,
		"no-trunc",
		false,
		"Don't truncate container ID",
	)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func newContainerParser(
	outputConfig *commonutils.OutputConfig, flags *ContainerFlags,
) (
	*commonutils.GadgetParser[containercollection.Container], error,
) {
	containerColumns := containercollection.GetColumns()

	idCol, ok := containerColumns.GetColumn("id")
	if !ok {
		return nil, fmt.Errorf(`"id" column doesn't exist`)
	}

	// By default, the "id" column is configured with width=13 and no fixed. In
	// this way, the auto-scale will do its magic when --no-trunc is not set.
	// Instead, when it is set, we must ensure auto-scale doesn't truncate it.
	if flags.noTrunc {
		idCol.Width = 64
		idCol.FixedWidth = true
	}

	return commonutils.NewGadgetParserWithRuntimeInfo(outputConfig, containerColumns)
}

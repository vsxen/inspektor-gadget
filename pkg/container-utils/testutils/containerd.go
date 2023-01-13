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

package testutils

import (
	"context"
	"fmt"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func RunContainerdContainer(ctx context.Context, t *testing.T, command string, options ...Option) {
	opts := defaultContainerOptions()
	for _, o := range options {
		o(opts)
	}

	opts.name = "asdf"
	opts.image = "docker.io/library/nginx:latest"
	namespace := "k8s.io"

	client, err := containerd.New("/run/containerd/containerd.sock",
		containerd.WithTimeout(30000000000),
		containerd.WithDefaultNamespace(namespace),
	)
	if err != nil {
		t.Fatalf("Failed to connect to containerd: %s", err)
		return
	}

	image, err := client.Pull(context.TODO(), opts.image)
	if err != nil {
		t.Fatalf("Failed to pull the image %q: %s", opts.image, err)
		return
	}

	var s specs.Spec

	container, err := client.NewContainer(context.TODO(), opts.name,
		containerd.WithImage(image),
		containerd.WithSpec(&s, oci.WithDefaultUnixDevices),
	)
	if err != nil {
		t.Fatalf("Failed to create container %q: %s", opts.name, err)
		return
	}

	task, err := container.NewTask(context.TODO(), cio.NewCreator())
	if err != nil {
		t.Fatalf("Failed to create task %q: %s", opts.name, err)
		return
	}

	status, err := task.Status(context.TODO())
	if err != nil {
		t.Fatalf("Failed to get status for task %q: %s", opts.name, err)
		return
	}
	fmt.Printf("Task is in state %q\n", status)
}

func RunDockerFailedContainerAAAAAAAAAAAA(ctx context.Context, t *testing.T) {
}

func RemoveDockerContainerAAAAAAAAAAAA(ctx context.Context, t *testing.T, name string) {
}

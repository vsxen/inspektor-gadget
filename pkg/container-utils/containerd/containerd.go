// Copyright 2019-2022 The Inspektor Gadget authors
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

package containerd

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/containerd"
	"github.com/moby/moby/errdefs"
	log "github.com/sirupsen/logrus"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	DefaultTimeout = 2 * time.Second

	LabelK8sContainerName         = "io.kubernetes.container.name"
	LabelK8sContainerdKind        = "io.cri-containerd.kind"
	LabelK8sContainerdKindSandbox = "sandbox"
)

type ContainerdClient struct {
	client *containerd.Client
}

func NewContainerdClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = runtimeclient.ContainerdDefaultSocketPath
	}

	client, err := containerd.New(socketPath,
		containerd.WithTimeout(DefaultTimeout),
		containerd.WithDefaultNamespace("k8s.io"),
	)
	if err != nil {
		return nil, err
	}

	return &ContainerdClient{
		client: client,
	}, nil
}

func (c *ContainerdClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *ContainerdClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := c.client.Containers(context.TODO(), "")
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, 0, len(containers))
	for _, container := range containers {
		if isSandboxContainer(container) {
			log.Debugf("ContainerdClient: container %q is a sandbox container. Temporary skipping it", container.ID())
			continue
		}

		task, err := getContainerdTask(container)
		if err != nil {
			return nil, err
		}

		containerData, err := taskAndContainerToContainerData(task, container)
		if err != nil {
			return nil, err
		}

		ret = append(ret, containerData)
	}

	return ret, nil
}

func (c *ContainerdClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	containerID, err := runtimeclient.ParseContainerID(runtimeclient.ContainerdName, containerID)
	if err != nil {
		return nil, err
	}

	containerData, _, _, err := c.getContainerDataAndContainerAndTask(containerID)
	if err != nil {
		return nil, err
	}
	return containerData, nil
}

func (c *ContainerdClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	containerID, err := runtimeclient.ParseContainerID(runtimeclient.ContainerdName, containerID)
	if err != nil {
		return nil, err
	}

	containerData, container, task, err := c.getContainerDataAndContainerAndTask(containerID)
	if err != nil {
		return nil, err
	}

	spec, err := container.Spec(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting spec for container %q: %w", containerID, err)
	}

	mountData := make([]runtimeclient.ContainerMountData, len(spec.Mounts))
	for i := range spec.Mounts {
		mount := spec.Mounts[i]
		mountData[i] = runtimeclient.ContainerMountData{
			Source:      mount.Source,
			Destination: mount.Destination,
		}
	}

	return &runtimeclient.ContainerDetailsData{
		ContainerData: *containerData,
		Pid:           int(task.Pid()),
		CgroupsPath:   spec.Linux.CgroupsPath,
		Mounts:        mountData,
	}, nil
}

func (c *ContainerdClient) getContainerDataAndContainerAndTask(containerID string) (*runtimeclient.ContainerData, containerd.Container, containerd.Task, error) {
	container, err := c.getContainerdContainer(containerID)
	if err != nil {
		return nil, nil, nil, err
	}

	task, err := getContainerdTask(container)
	if err != nil {
		return nil, nil, nil, err
	}

	containerData, err := taskAndContainerToContainerData(task, container)
	if err != nil {
		return nil, nil, nil, err
	}

	return containerData, container, task, nil
}

// getContainerdContainer returns the corresponding container.Container instance to
// the given id
func (c *ContainerdClient) getContainerdContainer(id string) (containerd.Container, error) {
	container, err := c.client.LoadContainer(context.TODO(), id)
	if err != nil {
		return nil, fmt.Errorf("loading container with id %q: %w", id, err)
	}

	if isSandboxContainer(container) {
		log.Debugf("ContainerdClient: container %q is a sandbox container. Temporary skipping it", container.ID())
		return nil, runtimeclient.ErrPauseContainer
	}

	return container, nil
}

// getContainerdTask returns the corresponding container.Task instance to
// the given containerd.Container. If there is no task, nil is returned without an error
func getContainerdTask(container containerd.Container) (containerd.Task, error) {
	task, err := container.Task(context.TODO(), nil)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("getting task for container %q: %w", container.ID(), err)
		}
		// else it is created, but not running
		log.Debugf("No task for %q", container.ID())
	}
	return task, nil
}

// Constructs a ContainerData from a containerd.Task and containerd.Container
// The extra containerd.Container parameter saves an additional call to the API
func taskAndContainerToContainerData(task containerd.Task, container containerd.Container) (*runtimeclient.ContainerData, error) {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing labels of container %q: %w", container.ID(), err)
	}

	// If the container exists, but there is no running task/proc, the state is created
	status := runtimeclient.StateCreated
	if task != nil {
		containerdStatus, err := task.Status(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("getting status of task for container %q: %w", container.ID(), err)
		}
		status = processStatusStateToRuntimeClientState(containerdStatus.Status)
	}

	containerData := &runtimeclient.ContainerData{
		ID:      container.ID(),
		Name:    getContainerName(container),
		State:   status,
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}

// Checks if the K8s Label for the Containerkind equals to sandbox
func isSandboxContainer(container containerd.Container) bool {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return false
	}

	if kind, ok := labels[LabelK8sContainerdKind]; ok {
		return kind == LabelK8sContainerdKindSandbox
	}

	return false
}

// Convert the state from container status to state of runtime client.
func processStatusStateToRuntimeClientState(status containerd.ProcessStatus) string {
	switch status {
	case containerd.Created:
		return runtimeclient.StateCreated
	case containerd.Running:
		return runtimeclient.StateRunning
	case containerd.Stopped:
		return runtimeclient.StateExited
	default:
		return runtimeclient.StateUnknown
	}
}

// getContainerName returns the name of the container. If the container is
// managed by Kubernetes, it returns the name of the container as defined in
// Kubernetes. Otherwise, it returns the container ID.
func getContainerName(container containerd.Container) string {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return container.ID()
	}

	if k8sName, ok := labels[LabelK8sContainerName]; ok {
		return k8sName
	}

	return container.ID()
}

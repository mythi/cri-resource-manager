// Copyright 2019 Intel Corporation. All Rights Reserved.
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

package topologyaware

import (
	"testing"

	system "github.com/intel/cri-resource-manager/pkg/sysfs"
	"github.com/intel/cri-resource-manager/pkg/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

func TestCpuHintScore(t *testing.T) {
	tcases := []struct {
		name     string
		expected float64
		hint     topology.TopologyHint
		cpus     cpuset.CPUSet
		disabled bool // TODO(rojkov): remove this field when the code is fixed.
	}{
		{
			name:     "handle zero cpu size gracefully",
			disabled: true,
		},
		{
			name: "handle unparsable cpu size gracefully",
			hint: topology.TopologyHint{
				CPUs: "unparsable",
			},
		},
		{
			name: "non-zero cpu size hint and empty CPUs",
			hint: topology.TopologyHint{
				CPUs: "1",
			},
		},
		{
			name: "hint corresponding to given CPU",
			hint: topology.TopologyHint{
				CPUs: "1,2",
			},
			cpus:     cpuset.NewCPUSet(1),
			expected: 0.5,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				t.Skipf("The case '%s' is skipped", tc.name)
			}
			actual := cpuHintScore(tc.hint, tc.cpus)
			if actual != tc.expected {
				t.Errorf("Expected %f, but got %f", tc.expected, actual)
			}
		})
	}
}

func TestNumaHintScore(t *testing.T) {
	tcases := []struct {
		name     string
		expected float64
		hint     topology.TopologyHint
		ids      []system.ID
	}{
		{
			name: "handle unparsable NUMAs gracefully",
			hint: topology.TopologyHint{
				NUMAs: "unparsable",
			},
		},
		{
			name: "non-zero NUMA hint and empty NUMAs",
			hint: topology.TopologyHint{
				NUMAs: "1",
			},
		},
		{
			name: "hint corresponding to a given ID",
			ids:  []system.ID{1},
			hint: topology.TopologyHint{
				NUMAs: "1,2",
			},
			expected: 1.0,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			actual := numaHintScore(tc.hint, tc.ids...)
			if actual != tc.expected {
				t.Errorf("Expected %f, but got %f", tc.expected, actual)
			}
		})
	}
}

func TestSocketHintScore(t *testing.T) {
	tcases := []struct {
		name     string
		expected float64
		hint     topology.TopologyHint
		id       system.ID
	}{
		{
			name: "handle unparsable Sockets gracefully",
			hint: topology.TopologyHint{
				Sockets: "unparsable",
			},
		},
		{
			name: "non-zero Sockets hint and empty Sockets",
			hint: topology.TopologyHint{
				Sockets: "1",
			},
		},
		{
			name: "hint corresponding to a given ID",
			id:   1,
			hint: topology.TopologyHint{
				Sockets: "1,2",
			},
			expected: 1.0,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			actual := socketHintScore(tc.hint, tc.id)
			if actual != tc.expected {
				t.Errorf("Expected %f, but got %f", tc.expected, actual)
			}
		})
	}
}

func TestHintCpus(t *testing.T) {
	tcases := []struct {
		name     string
		supply   *cpuSupply
		hint     topology.TopologyHint
		expected cpuset.CPUSet
	}{
		{
			name:   "handle unparsable Sockets gracefully",
			supply: &cpuSupply{},
			hint: topology.TopologyHint{
				Sockets: "unparsable",
			},
		},
		{
			name: "non-zero Sockets hint and empty system.Package",
			supply: &cpuSupply{
				node: &node{
					policy: &policy{
						sys: &mockSystem{},
					},
				},
			},
			hint: topology.TopologyHint{
				Sockets: "1",
			},
		},
		{
			name:   "handle unparsable NUMAs gracefully",
			supply: &cpuSupply{},
			hint: topology.TopologyHint{
				NUMAs: "unparsable",
			},
		},
		{
			name: "non-zero NUMAs hint and empty system.Node",
			supply: &cpuSupply{
				node: &node{
					policy: &policy{
						sys: &mockSystem{},
					},
				},
			},
			hint: topology.TopologyHint{
				NUMAs: "1",
			},
		},
		// TODO(rojkov): add tests for non-empty system.Package's (can't be done while system.Package is closed struct)
		{
			name:   "non-zero CPUs hint",
			supply: &cpuSupply{},
			hint: topology.TopologyHint{
				CPUs: "1",
			},
			expected: cpuset.NewCPUSet(1),
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.supply.hintCpus(tc.hint)
			if tc.expected.IsEmpty() && actual.IsEmpty() {
				return
			}
			if !tc.expected.Equals(actual) {
				t.Errorf("Expected %+v, but got %+v", tc.expected, actual)
			}
		})
	}
}

func TestString(t *testing.T) {
	tcases := []struct {
		name string
		fh   fakehints
		// maps are unordered, so there might be different legitimate results
		expected1 string
		expected2 string
	}{
		{
			name: "Empty",
		},
		{
			name: "non-empty CPUs",
			fh: fakehints{
				"key1": topology.TopologyHints{
					"testkey3": topology.TopologyHint{ // TODO(rojkov): this is bug - this value gets ignored
						CPUs:    "2",
						NUMAs:   "2",
						Sockets: "2",
					},
					"testkey2": topology.TopologyHint{
						CPUs:    "2",
						NUMAs:   "2",
						Sockets: "2",
					},
				},
				"key2": topology.TopologyHints{
					"testkey3": topology.TopologyHint{ // TODO(rojkov): this is bug - this value gets ignored
						CPUs:    "2",
						NUMAs:   "2",
						Sockets: "2",
					},
					"testkey2": topology.TopologyHint{
						CPUs:    "2",
						NUMAs:   "2",
						Sockets: "2",
					},
				},
			},
			expected1: "key1=cpus:2/nodes:2/sockets:2;key2=cpus:2/nodes:2/sockets:2",
			expected2: "key2=cpus:2/nodes:2/sockets:2;key1=cpus:2/nodes:2/sockets:2",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.fh.String()
			if actual != tc.expected1 && actual != tc.expected2 {
				t.Errorf("Expected %q, but got %q", tc.expected1, actual)
			}
		})
	}
}

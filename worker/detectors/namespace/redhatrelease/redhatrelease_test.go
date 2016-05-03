// Copyright 2015 clair authors
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

package redhatrelease

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors/namespace"
)

var redhatReleaseTests = []namespace.NamespaceTest{
	{
		ExpectedNamespace: database.Namespace{Name: "centos", Version: types.NewVersionUnsafe("6")},
		Data: map[string][]byte{
			"etc/centos-release": []byte(`CentOS release 6.6 (Final)`),
		},
	},
	{
		ExpectedNamespace: database.Namespace{Name: "centos", Version: types.NewVersionUnsafe("7")},
		Data: map[string][]byte{
			"etc/system-release": []byte(`CentOS Linux release 7.1.1503 (Core)`),
		},
	},
}

func TestRedhatReleaseNamespaceDetector(t *testing.T) {
	namespace.TestNamespaceDetector(t, &RedhatReleaseNamespaceDetector{}, redhatReleaseTests)
}

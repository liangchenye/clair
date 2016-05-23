// Copyright 2016 clair authors
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

package nodejs

import (
	"bufio"
	"io/ioutil"
	"os"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker/detectors/packages")

	NodejsPkg = "nodejs"
)

// NodejsNamespaceDetector implements FeaturesDetector and detects NamespaceDetector
// from /var/lib/dpkg/status file or /var/lib/rpm/Packages file
type NodejsNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("nodejs", &NodejsNamespaceDetector{})
}

func (detector *NodejsNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	if ns := detectDpkgNodejs(data); ns != nil {
		return ns
	} else if ns := detectRpmNodejs(data); ns != nil {
		return ns
	}
	return nil
}

func detectDpkgNodejs(data map[string][]byte) *database.Namespace {
	f, hasFile := data["var/lib/dpkg/status"]
	if !hasFile {
		return nil
	}

	isNodejs := false
	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			if pkgName := strings.TrimSpace(strings.TrimPrefix(line, "Package: ")); pkgName == NodejsPkg {
				isNodejs = true
			} else if isNodejs {
				return nil
			}
		} else if isNodejs && strings.HasPrefix(line, "Version: ") {
			return &database.Namespace{Name: NodejsPkg + ":" + strings.TrimPrefix(line, "Version: ")}
		}

	}

	return nil
}

func detectRpmNodejs(data map[string][]byte) *database.Namespace {
	f, hasFile := data["var/lib/rpm/Packages"]
	if !hasFile {
		return nil
	}

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.Errorf("could not create temporary folder for RPM %s detection: %s", NodejsPkg, err)
		return nil
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.Errorf("could not create temporary file for RPM %s detection: %s", NodejsPkg, err)
		return nil
	}

	out, err := utils.Exec(tmpDir, "rpm", "--dbpath", tmpDir, "-qi", NodejsPkg)
	if err != nil {
		log.Errorf("could not query RPM %s: %s. output: %s", NodejsPkg, err, string(out))
		return nil
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Version") {
			if values := strings.Split(line, ":"); len(values) == 2 {
				return &database.Namespace{Name: NodejsPkg + ":" + strings.TrimSpace(values[1])}
			}
		}

	}

	return nil
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *NodejsNamespaceDetector) GetRequiredFiles() []string {
	return []string{"^var/lib/rpm/Packages", "^var/lib/dpkg/status"}
}

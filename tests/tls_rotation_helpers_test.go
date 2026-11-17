/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tests

import (
	"os"
	"path/filepath"
	"testing"
)

const rotationServerHost = "127.0.0.1"

// writeMaterial replaces one of the files the proxy server and the agent are
// watching. The writes are deliberately not atomic: rotating a certificate and
// its key leaves a window in which the pair does not match, and the reloader is
// expected to keep serving the last valid material until both files land.
func writeMaterial(t *testing.T, dir, name string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
		t.Fatal(err)
	}
}

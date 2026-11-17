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
	"testing"

	"github.com/google/uuid"

	"sigs.k8s.io/apiserver-network-proxy/pkg/server"
	"sigs.k8s.io/apiserver-network-proxy/tests/framework"
)

func TestAgentTLSCertificateRotation(t *testing.T) {
	certsDir := t.TempDir()
	oldCA := framework.NewTestCA(t, "agent-rotation-old")
	newCA := framework.NewTestCA(t, "agent-rotation-new")
	oldServerCert, oldServerKey := oldCA.IssueServing(t, "server-old", rotationServerHost)
	oldClientCert, oldClientKey := oldCA.IssueClient(t, "agent-old")
	newServerCert, newServerKey := newCA.IssueServing(t, "server-new", rotationServerHost)
	newClientCert, newClientKey := newCA.IssueClient(t, "agent-new")
	writeMaterial(t, certsDir, framework.TestCAFile, oldCA.PEM)
	writeMaterial(t, certsDir, framework.TestServerCertFile, oldServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, oldServerKey)
	writeMaterial(t, certsDir, framework.TestAgentCertFile, oldClientCert)
	writeMaterial(t, certsDir, framework.TestAgentKeyFile, oldClientKey)

	ports, err := framework.FreePorts(1)
	if err != nil {
		t.Fatal(err)
	}
	opts := framework.ProxyServerOpts{Mode: server.ModeGRPC, ServerCount: 1, AgentPort: ports[0], CertsDir: certsDir}
	ps, err := Framework.ProxyServerRunner.Start(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Framework.AgentRunner.Start(t, framework.AgentOpts{AgentID: uuid.New().String(), ServerAddr: ps.AgentAddr(), CertsDir: certsDir})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	waitForConnectedServerCount(t, 1, a)
	ps.Stop()
	waitForConnectedServerCount(t, 0, a)

	writeMaterial(t, certsDir, framework.TestCAFile, newCA.PEM)
	writeMaterial(t, certsDir, framework.TestServerCertFile, newServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, newServerKey)
	writeMaterial(t, certsDir, framework.TestAgentCertFile, newClientCert)
	writeMaterial(t, certsDir, framework.TestAgentKeyFile, newClientKey)
	// The replacement server trusts only the new CA. Reconnecting the same
	// agent therefore requires both its new trust bundle and client identity.
	replacement, err := Framework.ProxyServerRunner.Start(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Stop()
	waitForConnectedServerCount(t, 1, a)
}

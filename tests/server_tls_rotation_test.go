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
	"bytes"
	"fmt"
	"testing"

	"sigs.k8s.io/apiserver-network-proxy/pkg/server"
	"sigs.k8s.io/apiserver-network-proxy/tests/framework"
)

func TestServerTLSCertificateRotation(t *testing.T) {
	certsDir := t.TempDir()
	oldCA := framework.NewTestCA(t, "server-rotation-old")
	newCA := framework.NewTestCA(t, "server-rotation-new")
	oldServerCert, oldServerKey := oldCA.IssueServing(t, "server-old", rotationServerHost)
	newServerCert, newServerKey := newCA.IssueServing(t, "server-new", rotationServerHost)
	oldClientCert, oldClientKey := oldCA.IssueClient(t, "client-old")
	newClientCert, newClientKey := newCA.IssueClient(t, "client-new")
	writeMaterial(t, certsDir, framework.TestCAFile, oldCA.PEM)
	writeMaterial(t, certsDir, framework.TestServerCertFile, oldServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, oldServerKey)
	ps, err := Framework.ProxyServerRunner.Start(t, framework.ProxyServerOpts{Mode: server.ModeGRPC, ServerCount: 1, CertsDir: certsDir})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Stop()

	roots := rotationCertPool(t, oldCA.PEM, newCA.PEM)
	oldClient := newRotationProbe(t, ps.AgentAddr(), roots, oldClientCert, oldClientKey)
	newClient := newRotationProbe(t, ps.AgentAddr(), roots, newClientCert, newClientKey)
	if _, err := oldClient.handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := newClient.handshake(); err == nil {
		t.Fatal("untrusted client certificate was accepted")
	}

	writeMaterial(t, certsDir, framework.TestCAFile, bytes.Join([][]byte{oldCA.PEM, newCA.PEM}, nil))
	writeMaterial(t, certsDir, framework.TestServerCertFile, newServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, newServerKey)
	waitFor(t, "the server to reload its identity and client CA bundle", func() error {
		peer, err := newClient.handshake()
		if err != nil {
			return err
		}
		if peer.Subject.CommonName != "server-new" {
			return fmt.Errorf("server presented %q", peer.Subject.CommonName)
		}
		_, err = oldClient.handshake()
		return err
	})

	writeMaterial(t, certsDir, framework.TestCAFile, newCA.PEM)
	waitFor(t, "the server to reject the retired client CA", func() error {
		if _, err := oldClient.handshake(); err == nil {
			return fmt.Errorf("retired client certificate was accepted")
		}
		_, err := newClient.handshake()
		return err
	})
}

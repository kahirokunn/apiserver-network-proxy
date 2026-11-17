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
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"sigs.k8s.io/apiserver-network-proxy/pkg/server"
	"sigs.k8s.io/apiserver-network-proxy/tests/framework"
)

// TestTLSCertificateRotation walks the proxy server and the agent through a
// staged CA rotation (distribute the new CA, swap the identities signed by it,
// retire the old CA) while an established tunnel connection stays open and is
// exercised after every stage.
func TestTLSCertificateRotation(t *testing.T) {
	ctx := context.Background()

	const (
		initialServerName = "anp-rotation-server-initial"
		rotatedServerName = "anp-rotation-server-rotated"
	)

	certsDir := t.TempDir()
	oldCA := framework.NewTestCA(t, "anp-rotation-ca-old")
	newCA := framework.NewTestCA(t, "anp-rotation-ca-new")

	initialServerCert, initialServerKey := oldCA.IssueServing(t, initialServerName, rotationServerHost)
	rotatedServerCert, rotatedServerKey := newCA.IssueServing(t, rotatedServerName, rotationServerHost)
	oldClientCert, oldClientKey := oldCA.IssueClient(t, "anp-rotation-agent-old")
	newClientCert, newClientKey := newCA.IssueClient(t, "anp-rotation-agent-new")

	writeMaterial(t, certsDir, framework.TestCAFile, oldCA.PEM)
	writeMaterial(t, certsDir, framework.TestServerCertFile, initialServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, initialServerKey)
	writeMaterial(t, certsDir, framework.TestAgentCertFile, oldClientCert)
	writeMaterial(t, certsDir, framework.TestAgentKeyFile, oldClientKey)

	// The agent has to find the restarted server at the end of the test, so the
	// port cannot be left to chance.
	ports, err := framework.FreePorts(1)
	if err != nil {
		t.Fatal(err)
	}
	serverOpts := framework.ProxyServerOpts{
		Mode:        server.ModeGRPC,
		ServerCount: 1,
		AgentPort:   ports[0],
		CertsDir:    certsDir,
	}
	ps, err := Framework.ProxyServerRunner.Start(t, serverOpts)
	if err != nil {
		t.Fatalf("Failed to start gRPC proxy server: %v", err)
	}

	a, err := Framework.AgentRunner.Start(t, framework.AgentOpts{
		AgentID:    uuid.New().String(),
		ServerAddr: ps.AgentAddr(),
		CertsDir:   certsDir,
	})
	if err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}
	defer a.Stop()
	waitForConnectedServerCount(t, 1, a)

	// Both probes verify the server against either CA, so they keep working
	// across the identity swap and only report on the server's decision about
	// the client certificate they present.
	trustBothCAs := rotationCertPool(t, oldCA.PEM, newCA.PEM)
	oldClient := newRotationProbe(t, ps.AgentAddr(), trustBothCAs, oldClientCert, oldClientKey)
	newClient := newRotationProbe(t, ps.AgentAddr(), trustBothCAs, newClientCert, newClientKey)

	// Baseline: the server accepts the old CA's client and rejects the new CA's.
	if _, err := oldClient.handshake(); err != nil {
		t.Fatalf("A client certificate from the initially trusted CA was rejected: %v", err)
	}
	if _, err := newClient.handshake(); err == nil {
		t.Fatal("A client certificate from a CA the server does not yet trust was accepted")
	}

	backendAddr := startEchoBackend(t)
	tunnel, err := createSingleUseGrpcTunnel(ctx, ps.FrontAddr())
	if err != nil {
		t.Fatalf("Failed to create tunnel: %v", err)
	}
	conn, err := tunnel.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to dial backend through the tunnel: %v", err)
	}
	assertTunnelAlive(t, conn, "initial")

	// Stage 1: publish the new CA alongside the old one, so that peers holding
	// a certificate from either CA are accepted while the rotation is underway.
	writeMaterial(t, certsDir, framework.TestCAFile, bytes.Join([][]byte{oldCA.PEM, newCA.PEM}, nil))
	waitFor(t, "the proxy server to trust the new CA", func() error {
		_, err := newClient.handshake()
		return err
	})
	assertTunnelAlive(t, conn, "after extending the trust bundle")

	// Stage 2: replace the identities. The agent's certificate is rotated here
	// too, but its effect is only visible on a new connection, which the server
	// restart at the end of the test forces.
	writeMaterial(t, certsDir, framework.TestServerCertFile, rotatedServerCert)
	writeMaterial(t, certsDir, framework.TestServerKeyFile, rotatedServerKey)
	writeMaterial(t, certsDir, framework.TestAgentCertFile, newClientCert)
	writeMaterial(t, certsDir, framework.TestAgentKeyFile, newClientKey)
	waitFor(t, "the proxy server to serve its rotated identity", func() error {
		peer, err := newClient.handshake()
		if err != nil {
			return err
		}
		if peer.Subject.CommonName != rotatedServerName {
			return fmt.Errorf("server presented certificate %q, want %q", peer.Subject.CommonName, rotatedServerName)
		}
		return nil
	})
	assertTunnelAlive(t, conn, "after rotating the identities")

	// Stage 3: retire the old CA. Acceptance and rejection are checked together
	// so a server that stopped accepting anything at all cannot pass.
	writeMaterial(t, certsDir, framework.TestCAFile, newCA.PEM)
	waitFor(t, "the proxy server to drop the old CA", func() error {
		if _, err := oldClient.handshake(); err == nil {
			return fmt.Errorf("a client certificate from the retired CA is still accepted")
		}
		if _, err := newClient.handshake(); err != nil {
			return fmt.Errorf("a client certificate from the new CA is rejected: %w", err)
		}
		return nil
	})
	assertTunnelAlive(t, conn, "after retiring the old CA")

	if err := conn.Close(); err != nil {
		t.Errorf("Failed to close the tunnel connection: %v", err)
	}

	// The agent's reload is only observable on a fresh handshake. Restart the
	// proxy server on the same port: it trusts only the new CA, so a successful
	// reconnect proves the agent picked up its rotated certificate.
	ps.Stop()
	waitForConnectedServerCount(t, 0, a)

	ps2, err := Framework.ProxyServerRunner.Start(t, serverOpts)
	if err != nil {
		t.Fatalf("Failed to restart gRPC proxy server: %v", err)
	}
	defer ps2.Stop()
	waitForConnectedServerCount(t, 1, a)
}

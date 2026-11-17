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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

const rotationServerHost = "127.0.0.1"
const rotationTimeout = 2 * time.Minute

// waitFor polls condition until it succeeds, reporting the most recent failure
// if it never does.
func waitFor(t *testing.T, description string, condition func() error) {
	t.Helper()
	var lastErr error
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, rotationTimeout, true,
		func(context.Context) (bool, error) {
			lastErr = condition()
			return lastErr == nil, nil
		})
	if err != nil {
		t.Fatalf("Timed out waiting for %s: %v", description, lastErr)
	}
}

// assertTunnelAlive sends a message through an already established tunnel
// connection and waits for the echo backend to send it back.
func assertTunnelAlive(t *testing.T, conn net.Conn, stage string) {
	t.Helper()
	sent := []byte(fmt.Sprintf("tunnel is alive %s", stage))
	received := make([]byte, len(sent))

	// Tunnel connections do not implement SetDeadline (it always returns "not
	// implemented"), so the round trip runs on its own goroutine and is bounded
	// by a timer. Closing the connection is what releases that goroutine.
	done := make(chan error, 1)
	go func() {
		if _, err := conn.Write(sent); err != nil {
			done <- fmt.Errorf("write failed: %w", err)
			return
		}
		if _, err := io.ReadFull(conn, received); err != nil {
			done <- fmt.Errorf("read failed: %w", err)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tunnel connection broken %s: %v", stage, err)
		}
		if !bytes.Equal(received, sent) {
			t.Fatalf("Tunnel connection returned %q %s, want %q", received, stage, sent)
		}
	case <-time.After(10 * time.Second):
		conn.Close()
		t.Fatalf("Timed out on the tunnel round trip %s", stage)
	}
}

// startEchoBackend runs a TCP echo server for the rest of the test and returns
// the address to dial it on.
func startEchoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				klog.Info(err)
				return
			}
			go echo(conn)
		}
	}()
	return ln.Addr().String()
}

// rotationProbe handshakes with the agent-facing listener directly, which is
// the only way to observe the server's current trust bundle and identity
// without disturbing the agent's connection.
type rotationProbe struct {
	addr        string
	roots       *x509.CertPool
	certificate tls.Certificate
}

func newRotationProbe(t *testing.T, addr string, roots *x509.CertPool, certPEM, keyPEM []byte) rotationProbe {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rotationProbe{addr: addr, roots: roots, certificate: certificate}
}

// handshake returns the certificate the server presented, or the error that
// ended the handshake.
func (p rotationProbe) handshake() (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", p.addr, &tls.Config{
		RootCAs:      p.roots,
		Certificates: []tls.Certificate{p.certificate},
		ServerName:   rotationServerHost,
		MinVersion:   tls.VersionTLS12,
		// Pinned to TLS 1.2. Under TLS 1.3 the client certificate is sent after
		// the client already considers the handshake complete, so a server that
		// rejects it fails a later read instead of the handshake, and this probe
		// would quietly stop testing rejection at all.
		MaxVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"}, // The agent-facing listener advertises only h2.
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, fmt.Errorf("server presented no certificate")
	}
	return peers[0], nil
}

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

func rotationCertPool(t *testing.T, pemBlocks ...[]byte) *x509.CertPool {
	t.Helper()
	pool, err := certutil.NewPoolFromBytes(bytes.Join(pemBlocks, nil))
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

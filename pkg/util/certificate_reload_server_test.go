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

package util //nolint:revive

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	certutil "k8s.io/client-go/util/cert"
)

func TestServerTLSConfigReloaderKeepsLastValidMaterialOnPartialUpdate(t *testing.T) {
	caFile, certFile, keyFile := tlsFilePaths(t)

	firstCA := newTestCA(t, "first-ca")
	firstServerCert, firstServerKey := firstCA.issue(t, "server-one")
	firstClientCert, firstClientKey := firstCA.issue(t, "client-one")
	writeTLSFiles(t, caFile, certFile, keyFile, firstCA.pem, firstServerCert, firstServerKey)

	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := reloader.tlsConfig()

	// Write the new CA and certificate but not the key, as a non-atomic update
	// would. Nothing may be published from the half-written state.
	secondCA := newTestCA(t, "second-ca")
	secondServerCert, secondServerKey := secondCA.issue(t, "server-two")
	secondClientCert, secondClientKey := secondCA.issue(t, "client-two")
	if err := os.WriteFile(caFile, secondCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, secondServerCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.material.reload(); err == nil {
		t.Fatal("mismatched certificate and key unexpectedly reloaded")
	}
	if got, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, firstClientCert, firstClientKey)); err != nil || got != "server-one" {
		t.Fatalf("last valid identity and trust were not retained: server=%q err=%v", got, err)
	}
	if _, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, secondClientCert, secondClientKey)); err == nil {
		t.Fatal("server accepted a client from the half-written trust bundle")
	}

	// Once the key lands, the whole update is applied together.
	if err := os.WriteFile(keyFile, secondServerKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.material.reload(); err != nil {
		t.Fatal(err)
	}
	if got, err := serverCertificateCommonName(tlsConfig, secondCA.clientConfig(t, secondClientCert, secondClientKey)); err != nil || got != "server-two" {
		t.Fatalf("update was not applied after the key landed: server=%q err=%v", got, err)
	}
}

func TestServerTLSConfigReloaderRejectsPartiallyInvalidTrustBundle(t *testing.T) {
	caFile, certFile, keyFile := tlsFilePaths(t)

	firstCA := newTestCA(t, "first-ca")
	firstServerCert, firstServerKey := firstCA.issue(t, "server-one")
	firstClientCert, firstClientKey := firstCA.issue(t, "client-one")
	writeTLSFiles(t, caFile, certFile, keyFile, firstCA.pem, firstServerCert, firstServerKey)

	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := reloader.tlsConfig()

	secondCA := newTestCA(t, "second-ca")
	secondClientCert, secondClientKey := secondCA.issue(t, "client-two")
	invalidCandidate := append(append([]byte(nil), secondCA.pem...), malformedCertificatePEM()...)
	if err := os.WriteFile(caFile, invalidCandidate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.material.reload(); err == nil {
		t.Fatal("partially invalid trust bundle unexpectedly reloaded")
	}
	if got, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, firstClientCert, firstClientKey)); err != nil || got != "server-one" {
		t.Fatalf("last valid server trust was not retained: server=%q err=%v", got, err)
	}
	if _, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, secondClientCert, secondClientKey)); err == nil {
		t.Fatal("server accepted a client from the partially loaded CA bundle")
	}

	if err := os.WriteFile(caFile, secondCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.material.reload(); err != nil {
		t.Fatal(err)
	}
	if got, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, secondClientCert, secondClientKey)); err != nil || got != "server-one" {
		t.Fatalf("server trust did not recover after repairing the bundle: server=%q err=%v", got, err)
	}
}

func TestReloadingServerTLSConfigWatchesProjectedFiles(t *testing.T) {
	dir := t.TempDir()
	caFile, certFile, keyFile := tlsFilePathsIn(dir)

	firstCA := newTestCA(t, "first-ca")
	firstServerCert, firstServerKey := firstCA.issue(t, "server-one")
	firstClientCert, firstClientKey := firstCA.issue(t, "client-one")
	writeProjectedTLSFiles(t, dir, "generation-1", firstCA.pem, firstServerCert, firstServerKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err := GetReloadingServerTLSConfig(ctx, caFile, certFile, keyFile, []string{"h2"}, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, firstClientCert, firstClientKey)); err != nil || got != "server-one" {
		t.Fatalf("initial handshake server = %q, err=%v", got, err)
	}

	secondCA := newTestCA(t, "second-ca")
	secondServerCert, secondServerKey := secondCA.issue(t, "server-two")
	secondClientCert, secondClientKey := secondCA.issue(t, "client-two")
	writeProjectedTLSFiles(t, dir, "generation-2", secondCA.pem, secondServerCert, secondServerKey)

	if err := waitForServerCertificate(tlsConfig, secondCA.clientConfig(t, secondClientCert, secondClientKey), "server-two"); err != nil {
		t.Fatal(err)
	}
}

func TestServerTLSConfigReloaderRejectsEmptyConfiguredClientCA(t *testing.T) {
	t.Run("initial load", func(t *testing.T) {
		caFile, certFile, keyFile := tlsFilePaths(t)

		ca := newTestCA(t, "ca")
		serverCert, serverKey := ca.issue(t, "server")
		writeTLSFiles(t, caFile, certFile, keyFile, nil, serverCert, serverKey)

		if _, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{}); err == nil {
			t.Fatal("empty configured client CA unexpectedly loaded")
		}
	})

	t.Run("reload", func(t *testing.T) {
		caFile, certFile, keyFile := tlsFilePaths(t)

		ca := newTestCA(t, "ca")
		serverCert, serverKey := ca.issue(t, "server")
		clientCert, clientKey := ca.issue(t, "client")
		writeTLSFiles(t, caFile, certFile, keyFile, ca.pem, serverCert, serverKey)

		reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig := reloader.tlsConfig()

		if err := os.WriteFile(caFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reloader.material.reload(); err == nil {
			t.Fatal("empty configured client CA unexpectedly reloaded")
		}
		if reloader.currentTLSConfig().ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", reloader.currentTLSConfig().ClientAuth)
		}
		if got, err := serverCertificateCommonName(tlsConfig, ca.clientConfig(t, clientCert, clientKey)); err != nil || got != "server" {
			t.Fatalf("last valid configuration was not retained: server=%q err=%v", got, err)
		}
	})
}

func TestServerTLSConfigReloaderPollingFallback(t *testing.T) {
	caFile, certFile, keyFile := tlsFilePaths(t)

	firstCA := newTestCA(t, "first-ca")
	firstServerCert, firstServerKey := firstCA.issue(t, "server-one")
	writeTLSFiles(t, caFile, certFile, keyFile, firstCA.pem, firstServerCert, firstServerKey)

	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloader.material.reloadInterval = 10 * time.Millisecond
	// Start only the reload loop, not the file watcher: a successful rotation
	// here proves polling reloads without fsnotify.
	go reloader.material.run(ctx)

	secondCA := newTestCA(t, "second-ca")
	secondServerCert, secondServerKey := secondCA.issue(t, "server-two")
	secondClientCert, secondClientKey := secondCA.issue(t, "client-two")
	writeTLSFiles(t, caFile, certFile, keyFile, secondCA.pem, secondServerCert, secondServerKey)
	if err := waitForServerCertificate(reloader.tlsConfig(), secondCA.clientConfig(t, secondClientCert, secondClientKey), "server-two"); err != nil {
		t.Fatal(err)
	}
}

func TestServerTLSConfigWithoutClientCA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	ca := newTestCA(t, "ca")
	serverCert, serverKey := ca.issue(t, "server")
	clientCert, clientKey := ca.issue(t, "client")
	writeTLSFiles(t, filepath.Join(dir, "unused-ca.crt"), certFile, keyFile, ca.pem, serverCert, serverKey)

	reloader, err := newServerTLSConfigReloader("", certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if reloader.currentTLSConfig().ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert", reloader.currentTLSConfig().ClientAuth)
	}
	if got, err := serverCertificateCommonName(reloader.tlsConfig(), ca.clientConfig(t, clientCert, clientKey)); err != nil || got != "server" {
		t.Fatalf("server without client CA = %q, err=%v", got, err)
	}
}

func TestServerTLSConfigReloaderPreservesNextProtos(t *testing.T) {
	caFile, certFile, keyFile := tlsFilePaths(t)

	ca := newTestCA(t, "ca")
	serverCert, serverKey := ca.issue(t, "server")
	writeTLSFiles(t, caFile, certFile, keyFile, ca.pem, serverCert, serverKey)

	nextProtos := []string{"h2", "custom"}
	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nextProtos, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := reloader.tlsConfig()

	configForClient, err := tlsConfig.GetConfigForClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(configForClient.NextProtos, nextProtos) {
		t.Fatalf("NextProtos = %v, want %v", configForClient.NextProtos, nextProtos)
	}
}

func serverCertificateCommonName(serverConfig, clientConfig *tls.Config) (string, error) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverRaw, serverConfig)
		defer serverRaw.Close()
		serverDone <- server.Handshake()
	}()

	client := tls.Client(clientRaw, clientConfig)
	defer clientRaw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientErr := client.HandshakeContext(ctx)
	_ = clientRaw.Close()
	serverErr := <-serverDone
	if clientErr != nil {
		return "", clientErr
	}
	if serverErr != nil {
		return "", serverErr
	}
	return client.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
}

func waitForServerCertificate(serverConfig, clientConfig *tls.Config, commonName string) error {
	var lastErr error
	err := wait.PollUntilContextTimeout(context.Background(), 20*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) {
		got, err := serverCertificateCommonName(serverConfig, clientConfig)
		switch {
		case err != nil:
			lastErr = err
		case got != commonName:
			lastErr = fmt.Errorf("server certificate common name = %q, want %q", got, commonName)
		default:
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("server TLS configuration did not reload: %v", lastErr)
	}
	return nil
}

func (ca testCA) clientConfig(t *testing.T, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootCAs, err := certutil.NewPoolFromBytes(ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{certificate},
		ServerName:   "proxy.test",
	}
}

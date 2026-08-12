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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc/credentials"
	"k8s.io/klog/v2"
)

const (
	// tlsReloadInterval is the poll period, the watch retry backoff, and the
	// cap on the reload retry backoff.
	tlsReloadInterval = time.Minute
	// tlsReloadRetryDelay is the initial backoff after a failed reload.
	tlsReloadRetryDelay = 5 * time.Millisecond
)

// TLSReloadHooks are optional callbacks invoked after every TLS reload
// attempt, for example to record metrics. Either field may be nil.
type TLSReloadHooks struct {
	// OnSuccess is called after every successful reload attempt, including
	// attempts that only confirmed the files are unchanged.
	OnSuccess func()
	// OnFailure is called after every failed reload attempt.
	OnFailure func()
}

// GetReloadingServerTLSConfig validates the configured files and returns a
// server TLS config whose identity and trust material are refreshed
// asynchronously. New handshakes use the latest valid material.
func GetReloadingServerTLSConfig(ctx context.Context, caFile, certFile, keyFile string, nextProtos []string, cipherSuites []uint16, minVersion uint16, hooks TLSReloadHooks) (*tls.Config, error) {
	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nextProtos, cipherSuites, minVersion, hooks)
	if err != nil {
		return nil, err
	}
	reloader.material.start(ctx)
	return reloader.tlsConfig(), nil
}

type serverTLSConfigReloader struct {
	material     *tlsMaterialReloader
	nextProtos   []string
	cipherSuites []uint16
	minVersion   uint16
}

func newServerTLSConfigReloader(caFile, certFile, keyFile string, nextProtos []string, cipherSuites []uint16, minVersion uint16, hooks TLSReloadHooks) (*serverTLSConfigReloader, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("server certificate and key files must be configured")
	}
	material, err := newTLSMaterialReloader(caFile, certFile, keyFile, hooks)
	if err != nil {
		return nil, err
	}
	return &serverTLSConfigReloader{
		material:     material,
		nextProtos:   append([]string(nil), nextProtos...),
		cipherSuites: append([]uint16(nil), cipherSuites...),
		minVersion:   minVersion,
	}, nil
}

func (r *serverTLSConfigReloader) currentTLSConfig() *tls.Config {
	material := r.material.current.Load()

	// The reloader owns nextProtos and cipherSuites, and crypto/tls treats the
	// returned config as read-only, so both slices can be shared. Session
	// ticket keys come from the listener's config rather than the one returned
	// here, so session resumption survives generation changes.
	config := &tls.Config{ // #nosec G402 -- the caller supplies the minimum version.
		Certificates: []tls.Certificate{*material.certificate},
		NextProtos:   r.nextProtos,
		MinVersion:   r.minVersion,
		CipherSuites: r.cipherSuites,
	}
	if r.material.caFile != "" {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = material.caPool
	}
	return config
}

func (r *serverTLSConfigReloader) tlsConfig() *tls.Config {
	config := r.currentTLSConfig().Clone()
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return r.currentTLSConfig(), nil
	}
	return config
}

// tlsMaterial is one published generation of validated TLS material. It also
// carries the PEM it was parsed from, so that a reload can detect that the
// files are unchanged without parsing them again.
type tlsMaterial struct {
	certificatePEM []byte
	privateKeyPEM  []byte
	caPEM          []byte
	certificate    *tls.Certificate
	caPool         *x509.CertPool
}

// tlsMaterialReloader reloads the configured TLS files as one unit: a new
// generation is published only after every file has been read, parsed and
// validated, and any failure keeps the previous generation in place until a
// retry succeeds.
type tlsMaterialReloader struct {
	caFile   string
	certFile string
	keyFile  string

	// reloadInterval is the poll period and the watch retry backoff.
	reloadInterval time.Duration

	hooks TLSReloadHooks

	mu      sync.Mutex
	current atomic.Pointer[tlsMaterial]
	// reloadCh schedules a reload; its capacity of one absorbs bursts of
	// notifications into a single pending reload.
	reloadCh chan struct{}
}

func newTLSMaterialReloader(caFile, certFile, keyFile string, hooks TLSReloadHooks) (*tlsMaterialReloader, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("certificate and key files must be configured together")
	}
	if certFile == "" && caFile == "" {
		return nil, fmt.Errorf("at least one TLS identity or CA file must be configured")
	}

	reloader := &tlsMaterialReloader{
		caFile:         caFile,
		certFile:       certFile,
		keyFile:        keyFile,
		reloadInterval: tlsReloadInterval,
		hooks:          hooks,
		reloadCh:       make(chan struct{}, 1),
	}
	if err := reloader.reload(); err != nil {
		return nil, err
	}
	if reloader.hooks.OnSuccess != nil {
		reloader.hooks.OnSuccess()
	}
	return reloader, nil
}

// start begins refreshing the material until ctx is canceled.
func (r *tlsMaterialReloader) start(ctx context.Context) {
	go r.watch(ctx)
	go r.run(ctx)
}

// reload publishes a new generation if any file changed. If any file fails to
// load or validate, the previously published generation stays in place.
func (r *tlsMaterialReloader) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var certificatePEM, privateKeyPEM, caPEM []byte
	var err error
	if r.certFile != "" {
		if certificatePEM, err = os.ReadFile(filepath.Clean(r.certFile)); err != nil {
			return fmt.Errorf("failed to read certificate %s: %w", r.certFile, err)
		}
		if privateKeyPEM, err = os.ReadFile(filepath.Clean(r.keyFile)); err != nil {
			return fmt.Errorf("failed to read key %s: %w", r.keyFile, err)
		}
	}
	if r.caFile != "" {
		if caPEM, err = os.ReadFile(filepath.Clean(r.caFile)); err != nil {
			return fmt.Errorf("failed to read CA certificate %s: %w", r.caFile, err)
		}
	}

	current := r.current.Load()
	if current != nil && bytes.Equal(certificatePEM, current.certificatePEM) &&
		bytes.Equal(privateKeyPEM, current.privateKeyPEM) && bytes.Equal(caPEM, current.caPEM) {
		return nil
	}

	next := &tlsMaterial{
		certificatePEM: certificatePEM,
		privateKeyPEM:  privateKeyPEM,
		caPEM:          caPEM,
	}
	if r.certFile != "" {
		certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to load X509 key pair: %w", err)
		}
		next.certificate = &certificate
	}
	if r.caFile != "" {
		caPool, err := newCACertPool(caPEM)
		if err != nil {
			return err
		}
		next.caPool = caPool
	}
	r.current.Store(next)
	klog.V(2).InfoS("Reloaded TLS material", "certificate", r.certFile, "key", r.keyFile, "ca", r.caFile)
	return nil
}

// requestReload schedules a reload; a reload already pending absorbs it.
func (r *tlsMaterialReloader) requestReload() {
	select {
	case r.reloadCh <- struct{}{}:
	default:
	}
}

// run reloads on change notifications, on a poll interval as a fallback, and
// with exponential backoff after failures, until ctx is canceled.
func (r *tlsMaterialReloader) run(ctx context.Context) {
	ticker := time.NewTicker(r.reloadInterval)
	defer ticker.Stop()

	retryDelay := tlsReloadRetryDelay
	var retryCh <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.reloadCh:
		case <-retryCh:
		}

		if err := r.reload(); err != nil {
			if r.hooks.OnFailure != nil {
				r.hooks.OnFailure()
			}
			klog.ErrorS(err, "Failed to reload TLS material; keeping the last valid material", "certificate", r.certFile, "key", r.keyFile, "ca", r.caFile)
			retryCh = time.After(retryDelay)
			retryDelay = min(2*retryDelay, r.reloadInterval)
			continue
		}
		if r.hooks.OnSuccess != nil {
			r.hooks.OnSuccess()
		}
		retryCh = nil
		retryDelay = tlsReloadRetryDelay
	}
}

func (r *tlsMaterialReloader) watch(ctx context.Context) {
	for {
		err := r.watchOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			klog.ErrorS(err, "TLS certificate watch failed; polling remains active")
		}

		timer := time.NewTimer(r.reloadInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *tlsMaterialReloader) watchOnce(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer watcher.Close()

	directories := r.watchDirectories()
	for directory := range directories {
		if err := watcher.Add(directory); err != nil {
			return fmt.Errorf("failed to watch directory %s: %w", directory, err)
		}
	}
	// Close the gap between the initial load and watch registration.
	r.requestReload()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("file watcher event channel closed")
			}
			r.requestReload()
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				if _, watched := directories[filepath.Clean(event.Name)]; watched {
					// The watch on a removed directory is dropped implicitly;
					// return so the caller re-establishes it.
					return fmt.Errorf("watched directory %s was removed or renamed", event.Name)
				}
			}
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("file watcher error channel closed")
			}
			if errors.Is(watchErr, fsnotify.ErrEventOverflow) {
				// Events were dropped; reload to catch up instead of tearing
				// down the watch.
				r.requestReload()
				continue
			}
			return watchErr
		}
	}
}

func (r *tlsMaterialReloader) watchDirectories() map[string]struct{} {
	directories := make(map[string]struct{}, 3)
	for _, file := range []string{r.caFile, r.certFile, r.keyFile} {
		if file != "" {
			directories[filepath.Dir(filepath.Clean(file))] = struct{}{}
		}
	}
	return directories
}

// GetReloadingClientTLSCredentials validates the configured files and returns
// client transport credentials whose identity and trust material are refreshed
// asynchronously. New connections use the latest valid material.
func GetReloadingClientTLSCredentials(ctx context.Context, caFile, certFile, keyFile, serverName string, protos []string, hooks TLSReloadHooks) (credentials.TransportCredentials, error) {
	if caFile == "" {
		return nil, fmt.Errorf("client CA file must be configured")
	}
	material, err := newTLSMaterialReloader(caFile, certFile, keyFile, hooks)
	if err != nil {
		return nil, err
	}
	material.start(ctx)

	baseConfig := &tls.Config{ // #nosec G402 -- TLS 1.2 is intentionally the minimum for compatibility.
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		NextProtos: append([]string(nil), protos...),
	}
	return newReloadingClientTLSCredentials(baseConfig, material), nil
}

func clientTLSConfig(baseConfig *tls.Config, material *tlsMaterial) *tls.Config {
	config := baseConfig.Clone()
	config.RootCAs = material.caPool
	if material.certificate != nil {
		config.Certificates = []tls.Certificate{*material.certificate}
	}
	return config
}

// reloadingClientTLSCredentials builds transport credentials from the latest
// validated TLS material for every handshake, so reconnects pick up rotated
// certificates without any redial logic.
type reloadingClientTLSCredentials struct {
	baseConfig *tls.Config
	// baseCreds answers Info() without rebuilding credentials on every call.
	baseCreds credentials.TransportCredentials
	material  *tlsMaterialReloader
}

func newReloadingClientTLSCredentials(baseConfig *tls.Config, material *tlsMaterialReloader) *reloadingClientTLSCredentials {
	return &reloadingClientTLSCredentials{
		baseConfig: baseConfig,
		baseCreds:  credentials.NewTLS(baseConfig),
		material:   material,
	}
}

func (c *reloadingClientTLSCredentials) currentCredentials() credentials.TransportCredentials {
	return credentials.NewTLS(clientTLSConfig(c.baseConfig, c.material.current.Load()))
}

func (c *reloadingClientTLSCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.currentCredentials().ClientHandshake(ctx, authority, rawConn)
}

func (c *reloadingClientTLSCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.currentCredentials().ServerHandshake(rawConn)
}

func (c *reloadingClientTLSCredentials) Info() credentials.ProtocolInfo {
	return c.baseCreds.Info()
}

func (c *reloadingClientTLSCredentials) Clone() credentials.TransportCredentials {
	return newReloadingClientTLSCredentials(c.baseConfig.Clone(), c.material)
}

// OverrideServerName implements credentials.TransportCredentials. Like the
// gRPC implementation it replaces, it is not safe for concurrent use; gRPC
// itself no longer calls this method.
func (c *reloadingClientTLSCredentials) OverrideServerName(serverName string) error {
	c.baseConfig.ServerName = serverName
	c.baseCreds = credentials.NewTLS(c.baseConfig)
	return nil
}

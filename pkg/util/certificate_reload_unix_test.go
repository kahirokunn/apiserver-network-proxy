//go:build unix

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

package util

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestTLSMaterialReloaderPreservesConfiguredPaths(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")
	generation := filepath.Join(archive, "generation")
	if err := os.MkdirAll(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current")
	if err := os.Symlink(generation, link); err != nil {
		t.Fatal(err)
	}
	caFile, certFile, keyFile := tlsFilePathsIn(archive)
	ca := newTestCA(t, "ca")
	cert, key := ca.issue(t, "server")
	writeTLSFiles(t, caFile, certFile, keyFile, ca.pem, cert, key)

	// The kernel resolves current before moving up to its parent.
	reloader, err := newTLSMaterialReloader(link+"/../ca.crt", link+"/../tls.crt", link+"/../tls.key", TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloader.current.Load().certificatePEM, cert) {
		t.Fatal("did not load the configured certificate")
	}
	dirs, err := reloader.watchDirectories()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !dirs.targets.Has(want) {
		t.Fatalf("watch directories %v do not include %q", dirs, want)
	}
}

func TestTLSWatchFollowsReplacedParentSymlink(t *testing.T) {
	if !watchTLSFiles {
		t.Skip("TLS files are polled on this platform")
	}
	root := t.TempDir()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(root, "current")
	if err := os.Symlink(first, current); err != nil {
		t.Fatal(err)
	}
	reloader := &tlsMaterialReloader{caFile: filepath.Join(current, "ca.crt"), reloadInterval: time.Hour, reloadCh: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go reloader.watch(ctx)
	waitForReload := func(stage string) {
		t.Helper()
		select {
		case <-reloader.reloadCh:
		case <-ctx.Done():
			t.Fatalf("no watch notification %s", stage)
		}
	}
	waitForReload("after registration")
	next := filepath.Join(root, "next")
	if err := os.Symlink(second, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, current); err != nil {
		t.Fatal(err)
	}
	waitForReload("after replacing the link")
	if err := os.WriteFile(filepath.Join(second, "ca.crt"), []byte("updated"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForReload("after writing in the new target")
}

func TestTLSWatchEventsThroughDirectoryAliases(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Two mount paths for the same directory have the same file identity.
	directories := tlsWatchDirectories{
		targets: sets.New("certs"),
		links:   sets.New("alias/current"),
	}
	events := directories.eventPaths(map[string]os.FileInfo{"certs": info, "alias": info, "other": other})
	if !events.targets.Equal(sets.New("certs", "alias")) || !events.links.Equal(sets.New("certs/current", "alias/current")) {
		t.Fatalf("unexpected event paths: targets=%v links=%v", events.targets, events.links)
	}
}

func TestTLSWatchesDetectReplacedAncestor(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	target := filepath.Join(parent, "tls")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &tlsMaterialReloader{caFile: filepath.Join(target, "ca.crt")}
	directories, err := r.watchDirectories()
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]os.FileInfo)
	for directory := range directories.targets {
		registered[directory], err = os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !r.watchesCurrent(directories, registered) {
		t.Fatal("unchanged directories need new watches")
	}
	// Renaming the ancestor leaves the watched directory itself in place.
	if err := os.Rename(parent, filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if r.watchesCurrent(directories, registered) {
		t.Fatal("watch still points to the directory under the old parent")
	}
}

func TestServerTLSConfigReloaderRejectsMixedProjectedGenerations(t *testing.T) {
	dir := t.TempDir()
	caFile, certFile, keyFile := tlsFilePathsIn(dir)
	firstCA := newTestCA(t, "first-ca")
	firstCert, firstKey := firstCA.issue(t, "server-one")
	firstClientCert, firstClientKey := firstCA.issue(t, "client-one")
	writeProjectedTLSFiles(t, dir, "generation-1", firstCA.pem, firstCert, firstKey)
	reloader, err := newServerTLSConfigReloader(caFile, certFile, keyFile, nil, nil, tls.VersionTLS12, TLSReloadHooks{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := reloader.tlsConfig()
	secondCA := newTestCA(t, "second-ca")
	secondCert, secondKey := secondCA.issue(t, "server-two")
	secondClientCert, secondClientKey := secondCA.issue(t, "client-two")

	read := func(path string) tlsFile {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		file := tlsFile{path: path}
		if err := file.readFrom(f, true); err != nil {
			t.Fatal(err)
		}
		return file
	}
	cert, key := read(certFile), read(keyFile)
	writeProjectedTLSFiles(t, dir, "generation-2", secondCA.pem, secondCert, secondKey)
	if err := reloader.material.publish(cert, key, read(caFile)); !errors.Is(err, errTLSFileChanged) {
		t.Fatalf("publishing files read across a Secret update: got %v, want %v", err, errTLSFileChanged)
	}

	if got, err := serverCertificateCommonName(tlsConfig, firstCA.clientConfig(t, firstClientCert, firstClientKey)); err != nil || got != "server-one" {
		t.Fatalf("last valid identity and trust were not retained: server=%q err=%v", got, err)
	}

	if err := reloader.material.reload(); err != nil {
		t.Fatal(err)
	}
	if got, err := serverCertificateCommonName(tlsConfig, secondCA.clientConfig(t, secondClientCert, secondClientKey)); err != nil || got != "server-two" {
		t.Fatalf("complete Secret generation was not loaded: server=%q err=%v", got, err)
	}
}

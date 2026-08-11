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

package testing_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	agent "sigs.k8s.io/apiserver-network-proxy/pkg/agent/metrics"
	server "sigs.k8s.io/apiserver-network-proxy/pkg/server/metrics"
)

func TestTLSReloadMetrics(t *testing.T) {
	const (
		serverFailures = "konnectivity_network_proxy_server_tls_certificate_reload_failure_total"
		serverSuccess  = "konnectivity_network_proxy_server_tls_certificate_last_reload_success_timestamp_seconds"
		agentFailures  = "konnectivity_network_proxy_agent_tls_certificate_reload_failure_total"
		agentSuccess   = "konnectivity_network_proxy_agent_tls_certificate_last_reload_success_timestamp_seconds"
		cluster        = `{purpose="cluster"}`
		frontend       = `{purpose="frontend"}`
	)

	server.Metrics.Reset()
	t.Cleanup(server.Metrics.Reset)
	clusterHooks := server.Metrics.TLSReloadHooks(server.TLSPurposeCluster)
	frontendHooks := server.Metrics.TLSReloadHooks(server.TLSPurposeFrontend)
	agentHooks := agent.Metrics.TLSReloadHooks()

	initial := gatherSamples(t)
	for _, name := range []string{serverFailures + cluster, serverFailures + frontend, serverSuccess + cluster, serverSuccess + frontend} {
		if v, ok := initial[name]; !ok || v != 0 {
			t.Fatalf("initial %s = %v, present = %t", name, v, ok)
		}
	}
	for _, name := range []string{agentFailures, agentSuccess} {
		if _, ok := initial[name]; !ok {
			t.Fatalf("missing initial %s", name)
		}
	}

	// Reuse the hooks after Reset removes the server's labeled series.
	server.Metrics.Reset()
	start := time.Now().Unix()
	clusterHooks.OnFailure()
	clusterHooks.OnSuccess()
	frontendHooks.OnFailure()
	frontendHooks.OnFailure()
	agentHooks.OnFailure()
	afterFailure := gatherSamples(t)
	if afterFailure[agentFailures] != initial[agentFailures]+1 || afterFailure[agentSuccess] != initial[agentSuccess] {
		t.Fatalf("agent reload failure changed failures from %v to %v and last success from %v to %v",
			initial[agentFailures], afterFailure[agentFailures], initial[agentSuccess], afterFailure[agentSuccess])
	}
	agentHooks.OnSuccess()
	end := time.Now().Unix() + 1

	got := gatherSamples(t)
	for name, want := range map[string]float64{
		serverFailures + cluster:  1,
		serverFailures + frontend: 2,
		agentFailures:             initial[agentFailures] + 1,
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
	for _, name := range []string{serverSuccess + cluster, agentSuccess} {
		if got[name] < float64(start) || got[name] >= float64(end) {
			t.Errorf("%s = %v, want a timestamp in [%d, %d)", name, got[name], start, end)
		}
	}
	if _, ok := got[serverSuccess+frontend]; ok {
		t.Error("frontend success recorded after a failed reload")
	}
}

func gatherSamples(t *testing.T) map[string]float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	samples, err := expfmt.ExtractSamples(&expfmt.DecodeOptions{}, families...)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]float64, len(samples))
	for _, sample := range samples {
		values[sample.Metric.String()] = float64(sample.Value)
	}
	return values
}

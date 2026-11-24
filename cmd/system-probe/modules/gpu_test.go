// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux && bpf && nvml

package modules

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	gpuconfig "github.com/DataDog/datadog-agent/pkg/gpu/config"
	"github.com/DataDog/datadog-agent/pkg/gpu/prm"
	ddnvml "github.com/DataDog/datadog-agent/pkg/gpu/safenvml"
	nvmltestutil "github.com/DataDog/datadog-agent/pkg/gpu/safenvml/testutil"
	gputestutil "github.com/DataDog/datadog-agent/pkg/gpu/testutil"
	"github.com/DataDog/datadog-agent/pkg/system-probe/api/module"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

func TestGPUModuleOrder(t *testing.T) {
	allModules := All()
	assert.Less(t, slices.Index(allModules, EventMonitor), slices.Index(allModules, GPUMonitoring))
}

func TestGPUModuleRegistersPRMEndpointWhenEnabled(t *testing.T) {
	router := http.NewServeMux()
	moduleRouter := module.NewRouter("gpu", router)
	gpuModule := &GPUMonitoringModule{
		cfg:        &gpuconfig.Config{PRMEndpointEnabled: true},
		prmHandler: &prm.Handler{},
	}

	err := gpuModule.Register(moduleRouter)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/gpu/prm-metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotContains(t, []int{http.StatusNotFound, http.StatusNotImplemented}, w.Code)
}

func TestGPUModulePRMEndpointDisabledReturnsNotImplemented(t *testing.T) {
	router := http.NewServeMux()
	moduleRouter := module.NewRouter("gpu", router)
	gpuModule := &GPUMonitoringModule{cfg: &gpuconfig.Config{PRMEndpointEnabled: false}}
	require.NoError(t, gpuModule.Register(moduleRouter))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/gpu/prm-metrics", nil))
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestGPUModuleDriverEventsDisabledDoesNotPanic(t *testing.T) {
	pkgconfigsetup.SystemProbe().SetInTest("gpu_monitoring.enable_ebpf_probes", false)
	pkgconfigsetup.SystemProbe().SetInTest("gpu_monitoring.driver_events_enabled", false)

	created, err := GPUMonitoring.Fn(nil, module.FactoryDependencies{})
	require.NoError(t, err)
	t.Cleanup(created.Close)

	router := http.NewServeMux()
	moduleRouter := module.NewRouter("gpu", router)
	require.NoError(t, created.Register(moduleRouter))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gpu/driver-events", nil))
	require.Equal(t, http.StatusNotImplemented, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gpu/check", nil))
	require.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestGPUModuleSurvivesDriverEventStartupError(t *testing.T) {
	ddnvml.WithMockNVML(t, gputestutil.NewMockNVML(gputestutil.WithDeviceCount(1)))
	pkgconfigsetup.SystemProbe().SetInTest("gpu_monitoring.enable_ebpf_probes", false)
	pkgconfigsetup.SystemProbe().SetInTest("gpu_monitoring.driver_events_enabled", true)

	created, err := GPUMonitoring.Fn(nil, module.FactoryDependencies{})
	require.NoError(t, err)
	t.Cleanup(created.Close)

	router := http.NewServeMux()
	moduleRouter := module.NewRouter("gpu", router)
	require.NoError(t, created.Register(moduleRouter))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gpu/driver-events", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestGetAgentPIDs(t *testing.T) {
	procRoot := kernel.CreateFakeProcFS(t, []kernel.FakeProcFSEntry{
		{Pid: 1, Exe: "/opt/datadog-agent/bin/agent/agent"},
		{Pid: 2, Exe: "/opt/datadog-agent/embedded/bin/trace-agent"},
		{Pid: 3, Exe: "/opt/datadog-agent/bin/agent/agent"},
	})

	pids, err := getAgentPIDs(procRoot)

	assert.NoError(t, err)
	assert.ElementsMatch(t, []uint32{1, 3}, pids)
}

func TestGPUModuleMigGrEndpoint(t *testing.T) {
	nvmltestutil.SetupMockNVML(t,
		gputestutil.WithDefaultMIGDevices(),
		gputestutil.WithGpmSupport(true),
		gputestutil.WithGpmMetricValues(map[nvml.GpmMetricId]gputestutil.MockGpmMetricValue{
			nvml.GPM_METRIC_GRAPHICS_UTIL: {Value: 42, Return: nvml.SUCCESS},
		}),
	)
	cache := ddnvml.NewDeviceCache()
	migDevices, err := cache.AllMigDevices()
	require.NoError(t, err)
	require.NotEmpty(t, migDevices)
	uuid := migDevices[0].GetDeviceInfo().UUID

	newModule := func(enabled bool) (*GPUMonitoringModule, *http.ServeMux) {
		router := http.NewServeMux()
		gpuModule := &GPUMonitoringModule{
			cfg:          &gpuconfig.Config{MigGrEndpointEnabled: enabled},
			deviceCache:  cache,
			migGrSamples: map[string]migGrSample{},
		}
		require.NoError(t, gpuModule.Register(module.NewRouter("gpu", router)))
		return gpuModule, router
	}
	get := func(router *http.ServeMux, query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gpu/mig-gr"+query, nil))
		return w
	}
	age := func(m *GPUMonitoringModule, d time.Duration) {
		s := m.migGrSamples[uuid]
		s.at = s.at.Add(-d)
		m.migGrSamples[uuid] = s
	}

	_, disabled := newModule(false)
	assert.Equal(t, http.StatusNotImplemented, get(disabled, "?uuid="+uuid).Code)

	m, router := newModule(true)
	assert.Equal(t, http.StatusBadRequest, get(router, "").Code)
	assert.Equal(t, http.StatusNotFound, get(router, "?uuid=MIG-unknown").Code)

	// The first request stores a baseline, a close second one keeps it
	assert.Equal(t, http.StatusServiceUnavailable, get(router, "?uuid="+uuid).Code)
	baseline := m.migGrSamples[uuid]
	assert.Equal(t, http.StatusServiceUnavailable, get(router, "?uuid="+uuid).Code)
	assert.Equal(t, baseline, m.migGrSamples[uuid])

	// A request one check interval later returns the value
	age(m, 15*time.Second)
	w := get(router, "?uuid="+uuid)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "42", strings.TrimSpace(w.Body.String()))

	// A baseline older than migGrMaxAge is replaced instead of averaging over the gap
	age(m, migGrMaxAge+time.Minute)
	assert.Equal(t, http.StatusServiceUnavailable, get(router, "?uuid="+uuid).Code)

	// An NVML release drops the stored samples
	m.dropMigGrSamples(true)
	assert.Empty(t, m.migGrSamples)
}

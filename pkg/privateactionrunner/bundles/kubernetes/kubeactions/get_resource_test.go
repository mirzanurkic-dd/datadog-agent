// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build kubeapiserver

package com_datadoghq_kubernetes_kubeactions

import (
	"testing"

	"github.com/stretchr/testify/assert"

	kubeactions "github.com/DataDog/datadog-agent/comp/kubeactions/kubeactions/def"
	support "github.com/DataDog/datadog-agent/pkg/privateactionrunner/bundle-support/kubernetes"
)

func TestRedactPayloads(t *testing.T) {
	t.Run("redacts every resource", func(t *testing.T) {
		result := redactPayloads(kubeactions.ExecutionResult{
			Status: kubeactions.StatusSuccess,
			Payloads: map[string][]byte{
				"pods/default/web": []byte(`{"spec":{"containers":[{"name":"main","args":["--token=hunter2"]}]}}`),
			},
		})

		assert.Equal(t, kubeactions.StatusSuccess, result.Status)
		assert.JSONEq(t, `{"spec":{"containers":[{"name":"main","args":["`+support.RedactedValue+`"]}]}}`, string(result.Payloads["pods/default/web"]))
	})

	t.Run("fails rather than leaking a resource it cannot redact", func(t *testing.T) {
		result := redactPayloads(kubeactions.ExecutionResult{
			Status:   kubeactions.StatusSuccess,
			Payloads: map[string][]byte{"pods/default/web": []byte("not json hunter2")},
		})

		assert.Equal(t, kubeactions.StatusFailed, result.Status)
		assert.Contains(t, result.Message, "failed to redact resource pods/default/web")
		assert.Empty(t, result.Payloads)
	})
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package com_datadoghq_kubernetes_customresources

import "github.com/DataDog/datadog-agent/pkg/privateactionrunner/types"

type KubernetesCustomResources struct {
	actions map[string]types.Action
}

func NewKubernetesCustomResources(allowedResources []string, redactSensitiveValues bool) *KubernetesCustomResources {
	policy := newResourcePolicy(allowedResources)
	return &KubernetesCustomResources{
		actions: map[string]types.Action{
			// Manual actions
			"createCustomObject":                 NewCreateCustomObjectHandler(policy, redactSensitiveValues),
			"deleteCustomObject":                 NewDeleteCustomObjectHandler(policy),
			"deleteMultipleCustomObjects":        NewDeleteMultipleCustomObjectsHandler(policy),
			"getCustomObject":                    NewGetCustomObjectHandler(policy, redactSensitiveValues),
			"listCustomObject":                   NewListCustomObjectHandler(policy, redactSensitiveValues),
			"patchCustomObject":                  NewPatchCustomObjectHandler(policy, redactSensitiveValues),
			"updateCustomObject":                 NewUpdateCustomObjectHandler(policy, redactSensitiveValues),
			"createClusterCustomObject":          NewCreateClusterCustomObjectHandler(policy, redactSensitiveValues),
			"deleteClusterCustomObject":          NewDeleteClusterCustomObjectHandler(policy),
			"deleteMultipleClusterCustomObjects": NewDeleteMultipleClusterCustomObjectsHandler(policy),
			"getClusterCustomObject":             NewGetClusterCustomObjectHandler(policy, redactSensitiveValues),
			"listClusterCustomObject":            NewListClusterCustomObjectHandler(policy, redactSensitiveValues),
			"patchClusterCustomObject":           NewPatchClusterCustomObjectHandler(policy, redactSensitiveValues),
			"updateClusterCustomObject":          NewUpdateClusterCustomObjectHandler(policy, redactSensitiveValues),
		},
	}
}

func (h *KubernetesCustomResources) GetAction(actionName string) types.Action {
	return h.actions[actionName]
}

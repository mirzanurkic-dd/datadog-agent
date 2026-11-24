// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package com_datadoghq_kubernetes_apps

import "github.com/DataDog/datadog-agent/pkg/privateactionrunner/types"

type KubernetesApps struct {
	actions map[string]types.Action
}

func NewKubernetesApps(redactSensitiveValues bool) *KubernetesApps {
	return &KubernetesApps{
		actions: map[string]types.Action{
			// Manual actions
			"restartDeployment":            NewRestartDeploymentHandler(redactSensitiveValues),
			"rollbackDeployment":           NewRollbackDeploymentHandler(),
			"scaleDeployment":              NewScaleDeploymentHandler(redactSensitiveValues),
			"scaleDeploymentVertically":    NewScaleDeploymentVerticallyHandler(redactSensitiveValues),
			"scaleStatefulSetHorizontally": NewScaleStatefulSetHorizontallyHandler(redactSensitiveValues),
			"scaleStatefulSetVertically":   NewScaleStatefulSetVerticallyHandler(redactSensitiveValues),
			// Auto-generated actions
			"createControllerRevision":          NewCreateControllerRevisionHandler(redactSensitiveValues),
			"updateControllerRevision":          NewUpdateControllerRevisionHandler(redactSensitiveValues),
			"deleteControllerRevision":          NewDeleteControllerRevisionHandler(),
			"deleteMultipleControllerRevisions": NewDeleteMultipleControllerRevisionsHandler(),
			"getControllerRevision":             NewGetControllerRevisionHandler(redactSensitiveValues),
			"listControllerRevision":            NewListControllerRevisionHandler(redactSensitiveValues),
			"patchControllerRevision":           NewPatchControllerRevisionHandler(redactSensitiveValues),
			"createDaemonSet":                   NewCreateDaemonSetHandler(redactSensitiveValues),
			"updateDaemonSet":                   NewUpdateDaemonSetHandler(redactSensitiveValues),
			"deleteDaemonSet":                   NewDeleteDaemonSetHandler(),
			"deleteMultipleDaemonSets":          NewDeleteMultipleDaemonSetsHandler(),
			"getDaemonSet":                      NewGetDaemonSetHandler(redactSensitiveValues),
			"listDaemonSet":                     NewListDaemonSetHandler(redactSensitiveValues),
			"patchDaemonSet":                    NewPatchDaemonSetHandler(redactSensitiveValues),
			"createDeployment":                  NewCreateDeploymentHandler(redactSensitiveValues),
			"updateDeployment":                  NewUpdateDeploymentHandler(redactSensitiveValues),
			"deleteDeployment":                  NewDeleteDeploymentHandler(),
			"deleteMultipleDeployments":         NewDeleteMultipleDeploymentsHandler(),
			"getDeployment":                     NewGetDeploymentHandler(redactSensitiveValues),
			"listDeployment":                    NewListDeploymentHandler(redactSensitiveValues),
			"patchDeployment":                   NewPatchDeploymentHandler(redactSensitiveValues),
			"createReplicaSet":                  NewCreateReplicaSetHandler(redactSensitiveValues),
			"updateReplicaSet":                  NewUpdateReplicaSetHandler(redactSensitiveValues),
			"deleteReplicaSet":                  NewDeleteReplicaSetHandler(),
			"deleteMultipleReplicaSets":         NewDeleteMultipleReplicaSetsHandler(),
			"getReplicaSet":                     NewGetReplicaSetHandler(redactSensitiveValues),
			"listReplicaSet":                    NewListReplicaSetHandler(redactSensitiveValues),
			"patchReplicaSet":                   NewPatchReplicaSetHandler(redactSensitiveValues),
			"createStatefulSet":                 NewCreateStatefulSetHandler(redactSensitiveValues),
			"updateStatefulSet":                 NewUpdateStatefulSetHandler(redactSensitiveValues),
			"deleteStatefulSet":                 NewDeleteStatefulSetHandler(),
			"deleteMultipleStatefulSets":        NewDeleteMultipleStatefulSetsHandler(),
			"getStatefulSet":                    NewGetStatefulSetHandler(redactSensitiveValues),
			"listStatefulSet":                   NewListStatefulSetHandler(redactSensitiveValues),
			"patchStatefulSet":                  NewPatchStatefulSetHandler(redactSensitiveValues),
		},
	}
}

func (h *KubernetesApps) GetAction(actionName string) types.Action {
	return h.actions[actionName]
}

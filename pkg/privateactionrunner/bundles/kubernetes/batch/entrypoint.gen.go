// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package com_datadoghq_kubernetes_batch

import "github.com/DataDog/datadog-agent/pkg/privateactionrunner/types"

type KubernetesBatch struct {
	actions map[string]types.Action
}

func NewKubernetesBatch(redactSensitiveValues bool) *KubernetesBatch {
	return &KubernetesBatch{
		actions: map[string]types.Action{
			// Manual actions
			"updateCronJobSchedule": NewUpdateCronJobScheduleHandler(redactSensitiveValues),
			// Auto-generated actions
			"createCronJob":          NewCreateCronJobHandler(redactSensitiveValues),
			"updateCronJob":          NewUpdateCronJobHandler(redactSensitiveValues),
			"deleteCronJob":          NewDeleteCronJobHandler(),
			"deleteMultipleCronJobs": NewDeleteMultipleCronJobsHandler(),
			"getCronJob":             NewGetCronJobHandler(redactSensitiveValues),
			"listCronJob":            NewListCronJobHandler(redactSensitiveValues),
			"patchCronJob":           NewPatchCronJobHandler(redactSensitiveValues),
			"createJob":              NewCreateJobHandler(redactSensitiveValues),
			"updateJob":              NewUpdateJobHandler(redactSensitiveValues),
			"deleteJob":              NewDeleteJobHandler(),
			"deleteMultipleJobs":     NewDeleteMultipleJobsHandler(),
			"getJob":                 NewGetJobHandler(redactSensitiveValues),
			"listJob":                NewListJobHandler(redactSensitiveValues),
			"patchJob":               NewPatchJobHandler(redactSensitiveValues),
		},
	}
}

func (h *KubernetesBatch) GetAction(actionName string) types.Action {
	return h.actions[actionName]
}

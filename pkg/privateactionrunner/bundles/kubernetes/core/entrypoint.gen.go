// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package com_datadoghq_kubernetes_core

import "github.com/DataDog/datadog-agent/pkg/privateactionrunner/types"

type KubernetesCore struct {
	actions map[string]types.Action
}

func NewKubernetesCore(redactSensitiveValues bool) *KubernetesCore {
	return &KubernetesCore{
		actions: map[string]types.Action{
			// Manual actions
			"getPodLogs":     NewGetPodLogsHandler(),
			"testConnection": NewTestConnectionHandler(),
			// Auto-generated actions
			"createConfigMap":                      NewCreateConfigMapHandler(),
			"updateConfigMap":                      NewUpdateConfigMapHandler(),
			"deleteConfigMap":                      NewDeleteConfigMapHandler(),
			"deleteMultipleConfigMaps":             NewDeleteMultipleConfigMapsHandler(),
			"getConfigMap":                         NewGetConfigMapHandler(),
			"listConfigMap":                        NewListConfigMapHandler(),
			"patchConfigMap":                       NewPatchConfigMapHandler(),
			"createEndpoints":                      NewCreateEndpointsHandler(),
			"updateEndpoints":                      NewUpdateEndpointsHandler(),
			"deleteEndpoints":                      NewDeleteEndpointsHandler(),
			"deleteMultipleEndpoints":              NewDeleteMultipleEndpointsHandler(),
			"getEndpoints":                         NewGetEndpointsHandler(),
			"listEndpoints":                        NewListEndpointsHandler(),
			"patchEndpoints":                       NewPatchEndpointsHandler(),
			"createEvent":                          NewCreateEventHandler(),
			"updateEvent":                          NewUpdateEventHandler(),
			"deleteEvent":                          NewDeleteEventHandler(),
			"deleteMultipleEvents":                 NewDeleteMultipleEventsHandler(),
			"getEvent":                             NewGetEventHandler(),
			"listEvent":                            NewListEventHandler(),
			"patchEvent":                           NewPatchEventHandler(),
			"createLimitRange":                     NewCreateLimitRangeHandler(),
			"updateLimitRange":                     NewUpdateLimitRangeHandler(),
			"deleteLimitRange":                     NewDeleteLimitRangeHandler(),
			"deleteMultipleLimitRanges":            NewDeleteMultipleLimitRangesHandler(),
			"getLimitRange":                        NewGetLimitRangeHandler(),
			"listLimitRange":                       NewListLimitRangeHandler(),
			"patchLimitRange":                      NewPatchLimitRangeHandler(),
			"createNamespace":                      NewCreateNamespaceHandler(),
			"updateNamespace":                      NewUpdateNamespaceHandler(),
			"deleteNamespace":                      NewDeleteNamespaceHandler(),
			"getNamespace":                         NewGetNamespaceHandler(),
			"listNamespace":                        NewListNamespaceHandler(),
			"patchNamespace":                       NewPatchNamespaceHandler(),
			"createNode":                           NewCreateNodeHandler(),
			"updateNode":                           NewUpdateNodeHandler(),
			"deleteNode":                           NewDeleteNodeHandler(),
			"deleteMultipleNodes":                  NewDeleteMultipleNodesHandler(),
			"getNode":                              NewGetNodeHandler(),
			"listNode":                             NewListNodeHandler(),
			"patchNode":                            NewPatchNodeHandler(),
			"createPersistentVolume":               NewCreatePersistentVolumeHandler(),
			"updatePersistentVolume":               NewUpdatePersistentVolumeHandler(),
			"deletePersistentVolume":               NewDeletePersistentVolumeHandler(),
			"deleteMultiplePersistentVolumes":      NewDeleteMultiplePersistentVolumesHandler(),
			"getPersistentVolume":                  NewGetPersistentVolumeHandler(),
			"listPersistentVolume":                 NewListPersistentVolumeHandler(),
			"patchPersistentVolume":                NewPatchPersistentVolumeHandler(),
			"createPersistentVolumeClaim":          NewCreatePersistentVolumeClaimHandler(),
			"updatePersistentVolumeClaim":          NewUpdatePersistentVolumeClaimHandler(),
			"deletePersistentVolumeClaim":          NewDeletePersistentVolumeClaimHandler(),
			"deleteMultiplePersistentVolumeClaims": NewDeleteMultiplePersistentVolumeClaimsHandler(),
			"getPersistentVolumeClaim":             NewGetPersistentVolumeClaimHandler(),
			"listPersistentVolumeClaim":            NewListPersistentVolumeClaimHandler(),
			"patchPersistentVolumeClaim":           NewPatchPersistentVolumeClaimHandler(),
			"createPod":                            NewCreatePodHandler(redactSensitiveValues),
			"updatePod":                            NewUpdatePodHandler(redactSensitiveValues),
			"deletePod":                            NewDeletePodHandler(),
			"deleteMultiplePods":                   NewDeleteMultiplePodsHandler(),
			"getPod":                               NewGetPodHandler(redactSensitiveValues),
			"listPod":                              NewListPodHandler(redactSensitiveValues),
			"patchPod":                             NewPatchPodHandler(redactSensitiveValues),
			"createPodTemplate":                    NewCreatePodTemplateHandler(redactSensitiveValues),
			"updatePodTemplate":                    NewUpdatePodTemplateHandler(redactSensitiveValues),
			"deletePodTemplate":                    NewDeletePodTemplateHandler(),
			"deleteMultiplePodTemplates":           NewDeleteMultiplePodTemplatesHandler(),
			"getPodTemplate":                       NewGetPodTemplateHandler(redactSensitiveValues),
			"listPodTemplate":                      NewListPodTemplateHandler(redactSensitiveValues),
			"patchPodTemplate":                     NewPatchPodTemplateHandler(redactSensitiveValues),
			"createReplicationController":          NewCreateReplicationControllerHandler(redactSensitiveValues),
			"updateReplicationController":          NewUpdateReplicationControllerHandler(redactSensitiveValues),
			"deleteReplicationController":          NewDeleteReplicationControllerHandler(),
			"deleteMultipleReplicationControllers": NewDeleteMultipleReplicationControllersHandler(),
			"getReplicationController":             NewGetReplicationControllerHandler(redactSensitiveValues),
			"listReplicationController":            NewListReplicationControllerHandler(redactSensitiveValues),
			"patchReplicationController":           NewPatchReplicationControllerHandler(redactSensitiveValues),
			"createResourceQuota":                  NewCreateResourceQuotaHandler(),
			"updateResourceQuota":                  NewUpdateResourceQuotaHandler(),
			"deleteResourceQuota":                  NewDeleteResourceQuotaHandler(),
			"deleteMultipleResourceQuotas":         NewDeleteMultipleResourceQuotasHandler(),
			"getResourceQuota":                     NewGetResourceQuotaHandler(),
			"listResourceQuota":                    NewListResourceQuotaHandler(),
			"patchResourceQuota":                   NewPatchResourceQuotaHandler(),
			"createService":                        NewCreateServiceHandler(),
			"updateService":                        NewUpdateServiceHandler(),
			"deleteService":                        NewDeleteServiceHandler(),
			"getService":                           NewGetServiceHandler(),
			"listService":                          NewListServiceHandler(),
			"patchService":                         NewPatchServiceHandler(),
			"createServiceAccount":                 NewCreateServiceAccountHandler(),
			"updateServiceAccount":                 NewUpdateServiceAccountHandler(),
			"deleteServiceAccount":                 NewDeleteServiceAccountHandler(),
			"deleteMultipleServiceAccounts":        NewDeleteMultipleServiceAccountsHandler(),
			"getServiceAccount":                    NewGetServiceAccountHandler(),
			"listServiceAccount":                   NewListServiceAccountHandler(),
			"patchServiceAccount":                  NewPatchServiceAccountHandler(),
		},
	}
}

func (h *KubernetesCore) GetAction(actionName string) types.Action {
	return h.actions[actionName]
}

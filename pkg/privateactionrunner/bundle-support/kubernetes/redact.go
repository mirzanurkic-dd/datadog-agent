// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package kubernetes

// Redaction of sensitive values from Kubernetes objects returned by actions,
// gated by private_action_runner.kubernetes_redact_sensitive_values.
//
// These adapters use the Agent's shared Kubernetes scrubbing rules.

import (
	"encoding/json"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/DataDog/datadog-agent/pkg/redact"
)

// The scrubber is read-only after initialization and can be shared by actions.
var sensitiveValuesScrubber = redact.NewDefaultDataScrubber()

// RedactedValue masks data that cannot be parsed for scrubbing.
const RedactedValue = "********"

// RedactPod redacts the sensitive values of a pod.
func RedactPod(pod *corev1.Pod) {
	redactObjectMeta(&pod.ObjectMeta)
	redact.ScrubPod(pod, sensitiveValuesScrubber)
	redactEphemeralContainers(&pod.Spec)
}

// RedactPodTemplate redacts the sensitive values of a pod template.
func RedactPodTemplate(podTemplate *corev1.PodTemplate) {
	redactObjectMeta(&podTemplate.ObjectMeta)
	redactPodTemplateSpec(&podTemplate.Template)
}

// RedactReplicationController redacts the sensitive values of a replication controller.
func RedactReplicationController(controller *corev1.ReplicationController) {
	redactObjectMeta(&controller.ObjectMeta)
	if controller.Spec.Template != nil {
		redactPodTemplateSpec(controller.Spec.Template)
	}
}

// RedactDeployment redacts the sensitive values of a deployment.
func RedactDeployment(deployment *appsv1.Deployment) {
	redactObjectMeta(&deployment.ObjectMeta)
	redactPodTemplateSpec(&deployment.Spec.Template)
}

// RedactDaemonSet redacts the sensitive values of a daemon set.
func RedactDaemonSet(daemonSet *appsv1.DaemonSet) {
	redactObjectMeta(&daemonSet.ObjectMeta)
	redactPodTemplateSpec(&daemonSet.Spec.Template)
}

// RedactReplicaSet redacts the sensitive values of a replica set.
func RedactReplicaSet(replicaSet *appsv1.ReplicaSet) {
	redactObjectMeta(&replicaSet.ObjectMeta)
	redactPodTemplateSpec(&replicaSet.Spec.Template)
}

// RedactStatefulSet redacts the sensitive values of a stateful set.
func RedactStatefulSet(statefulSet *appsv1.StatefulSet) {
	redactObjectMeta(&statefulSet.ObjectMeta)
	redactPodTemplateSpec(&statefulSet.Spec.Template)
}

// RedactControllerRevision redacts the sensitive values of a controller
// revision, whose data embeds a pod template as raw JSON. Data that cannot be
// parsed is masked entirely.
func RedactControllerRevision(revision *appsv1.ControllerRevision) {
	redactObjectMeta(&revision.ObjectMeta)
	revision.Data.Object = nil
	if len(revision.Data.Raw) == 0 {
		return
	}
	redacted, err := RedactJSON(revision.Data.Raw)
	if err != nil {
		redacted, _ = json.Marshal(RedactedValue)
	}
	revision.Data.Raw = redacted
}

// RedactJob redacts the sensitive values of a job.
func RedactJob(job *batchv1.Job) {
	redactObjectMeta(&job.ObjectMeta)
	redactPodTemplateSpec(&job.Spec.Template)
}

// RedactCronJob redacts the sensitive values of a cron job.
func RedactCronJob(cronJob *batchv1.CronJob) {
	redactObjectMeta(&cronJob.ObjectMeta)
	redactObjectMeta(&cronJob.Spec.JobTemplate.ObjectMeta)
	redactPodTemplateSpec(&cronJob.Spec.JobTemplate.Spec.Template)
}

func redactObjectMeta(meta *metav1.ObjectMeta) {
	redact.RemoveSensitiveAnnotationsAndLabels(meta.Annotations, meta.Labels)
	for key, value := range meta.Annotations {
		meta.Annotations[key] = sensitiveValuesScrubber.ScrubAnnotationValue(value)
	}
}

func redactPodTemplateSpec(template *corev1.PodTemplateSpec) {
	redactObjectMeta(&template.ObjectMeta)
	redact.ScrubPodTemplateSpec(template, sensitiveValuesScrubber)
	redactEphemeralContainers(&template.Spec)
}

func redactEphemeralContainers(spec *corev1.PodSpec) {
	for i := range spec.EphemeralContainers {
		// Adapt ephemeral containers to the existing container rules without
		// changing the shared scrubber's behavior for other callers.
		pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
			corev1.Container(spec.EphemeralContainers[i].EphemeralContainerCommon),
		}}}
		redact.ScrubPod(&pod, sensitiveValuesScrubber)
		spec.EphemeralContainers[i].EphemeralContainerCommon = corev1.EphemeralContainerCommon(pod.Spec.Containers[0])
	}
}

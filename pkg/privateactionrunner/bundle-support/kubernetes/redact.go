// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package kubernetes

// Redaction of sensitive values from Kubernetes objects returned by actions,
// gated by private_action_runner.kubernetes_redact_sensitive_values.
//
// Wherever an object embeds a pod spec, every container (init, regular and
// ephemeral) gets:
//   - its env values masked; env names and valueFrom references are kept,
//   - its command and args entries masked.
//
// The kubectl last-applied-configuration annotation of these objects is masked
// too, as it holds a full copy of the applied spec.

import (
	"encoding/json"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RedactedValue replaces every redacted value.
const RedactedValue = "*****[REDACTED]*****"

const lastAppliedConfigAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// RedactPod redacts the sensitive values of a pod.
func RedactPod(pod *corev1.Pod) {
	redactObjectMeta(&pod.ObjectMeta)
	redactPodSpec(&pod.Spec)
}

// RedactPodTemplate redacts the sensitive values of a pod template.
func RedactPodTemplate(podTemplate *corev1.PodTemplate) {
	redactObjectMeta(&podTemplate.ObjectMeta)
	redactPodSpec(&podTemplate.Template.Spec)
}

// RedactReplicationController redacts the sensitive values of a replication controller.
func RedactReplicationController(controller *corev1.ReplicationController) {
	redactObjectMeta(&controller.ObjectMeta)
	if controller.Spec.Template != nil {
		redactPodSpec(&controller.Spec.Template.Spec)
	}
}

// RedactDeployment redacts the sensitive values of a deployment.
func RedactDeployment(deployment *appsv1.Deployment) {
	redactObjectMeta(&deployment.ObjectMeta)
	redactPodSpec(&deployment.Spec.Template.Spec)
}

// RedactDaemonSet redacts the sensitive values of a daemon set.
func RedactDaemonSet(daemonSet *appsv1.DaemonSet) {
	redactObjectMeta(&daemonSet.ObjectMeta)
	redactPodSpec(&daemonSet.Spec.Template.Spec)
}

// RedactReplicaSet redacts the sensitive values of a replica set.
func RedactReplicaSet(replicaSet *appsv1.ReplicaSet) {
	redactObjectMeta(&replicaSet.ObjectMeta)
	redactPodSpec(&replicaSet.Spec.Template.Spec)
}

// RedactStatefulSet redacts the sensitive values of a stateful set.
func RedactStatefulSet(statefulSet *appsv1.StatefulSet) {
	redactObjectMeta(&statefulSet.ObjectMeta)
	redactPodSpec(&statefulSet.Spec.Template.Spec)
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
	redactPodSpec(&job.Spec.Template.Spec)
}

// RedactCronJob redacts the sensitive values of a cron job.
func RedactCronJob(cronJob *batchv1.CronJob) {
	redactObjectMeta(&cronJob.ObjectMeta)
	redactPodSpec(&cronJob.Spec.JobTemplate.Spec.Template.Spec)
}

func redactObjectMeta(meta *metav1.ObjectMeta) {
	if _, found := meta.Annotations[lastAppliedConfigAnnotation]; found {
		meta.Annotations[lastAppliedConfigAnnotation] = RedactedValue
	}
}

func redactPodSpec(spec *corev1.PodSpec) {
	for i := range spec.InitContainers {
		redactContainer(&spec.InitContainers[i])
	}
	for i := range spec.Containers {
		redactContainer(&spec.Containers[i])
	}
	for i := range spec.EphemeralContainers {
		container := &spec.EphemeralContainers[i].EphemeralContainerCommon
		redactEnv(container.Env)
		maskAll(container.Command)
		maskAll(container.Args)
	}
}

func redactContainer(container *corev1.Container) {
	redactEnv(container.Env)
	maskAll(container.Command)
	maskAll(container.Args)
}

func redactEnv(env []corev1.EnvVar) {
	for i := range env {
		if env[i].Value != "" {
			env[i].Value = RedactedValue
		}
	}
}

func maskAll(values []string) {
	for i := range values {
		values[i] = RedactedValue
	}
}

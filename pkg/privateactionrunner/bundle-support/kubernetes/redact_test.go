// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package kubernetes

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const secret = "hunter2"

func sensitiveContainer() corev1.Container {
	return corev1.Container{
		Name:    "main",
		Image:   "nginx:1.27",
		Command: []string{"sh", "-c"},
		Args:    []string{"--password=" + secret},
		Env: []corev1.EnvVar{
			{Name: "DB_PASSWORD", Value: secret},
			{Name: "API_KEY", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
					Key:                  "api-key",
				},
			}},
		},
	}
}

func sensitivePodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		InitContainers: []corev1.Container{sensitiveContainer()},
		Containers:     []corev1.Container{sensitiveContainer()},
		EphemeralContainers: []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon(sensitiveContainer()),
		}},
	}
}

func sensitiveObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: "web",
		Annotations: map[string]string{
			lastAppliedConfigAnnotation: `{"env":[{"name":"DB_PASSWORD","value":"` + secret + `"}]}`,
			"team":                      "platform",
		},
	}
}

func sensitivePodTemplateSpec() corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{Spec: sensitivePodSpec()}
}

func assertContainerRedacted(t *testing.T, container corev1.Container) {
	t.Helper()
	assert.Equal(t, "nginx:1.27", container.Image, "other fields are kept")
	assert.Equal(t, []string{RedactedValue, RedactedValue}, container.Command)
	assert.Equal(t, []string{RedactedValue}, container.Args)
	require.Len(t, container.Env, 2)
	assert.Equal(t, corev1.EnvVar{Name: "DB_PASSWORD", Value: RedactedValue}, container.Env[0])
	assert.Equal(t, "API_KEY", container.Env[1].Name, "env names are kept")
	assert.Empty(t, container.Env[1].Value, "valueFrom env vars get no value")
	assert.NotNil(t, container.Env[1].ValueFrom, "valueFrom references are kept")
}

func assertPodSpecRedacted(t *testing.T, spec corev1.PodSpec) {
	t.Helper()
	assertContainerRedacted(t, spec.InitContainers[0])
	assertContainerRedacted(t, spec.Containers[0])
	assertContainerRedacted(t, corev1.Container(spec.EphemeralContainers[0].EphemeralContainerCommon))
}

func assertObjectMetaRedacted(t *testing.T, meta metav1.ObjectMeta) {
	t.Helper()
	assert.Equal(t, RedactedValue, meta.Annotations[lastAppliedConfigAnnotation])
	assert.Equal(t, "platform", meta.Annotations["team"], "other annotations are kept")
}

func TestRedactTypedResources(t *testing.T) {
	tests := []struct {
		name   string
		redact func() (metav1.ObjectMeta, corev1.PodSpec)
	}{
		{"Pod", func() (metav1.ObjectMeta, corev1.PodSpec) {
			pod := &corev1.Pod{ObjectMeta: sensitiveObjectMeta(), Spec: sensitivePodSpec()}
			RedactPod(pod)
			return pod.ObjectMeta, pod.Spec
		}},
		{"PodTemplate", func() (metav1.ObjectMeta, corev1.PodSpec) {
			podTemplate := &corev1.PodTemplate{ObjectMeta: sensitiveObjectMeta(), Template: sensitivePodTemplateSpec()}
			RedactPodTemplate(podTemplate)
			return podTemplate.ObjectMeta, podTemplate.Template.Spec
		}},
		{"ReplicationController", func() (metav1.ObjectMeta, corev1.PodSpec) {
			template := sensitivePodTemplateSpec()
			controller := &corev1.ReplicationController{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       corev1.ReplicationControllerSpec{Template: &template},
			}
			RedactReplicationController(controller)
			return controller.ObjectMeta, controller.Spec.Template.Spec
		}},
		{"Deployment", func() (metav1.ObjectMeta, corev1.PodSpec) {
			deployment := &appsv1.Deployment{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       appsv1.DeploymentSpec{Template: sensitivePodTemplateSpec()},
			}
			RedactDeployment(deployment)
			return deployment.ObjectMeta, deployment.Spec.Template.Spec
		}},
		{"DaemonSet", func() (metav1.ObjectMeta, corev1.PodSpec) {
			daemonSet := &appsv1.DaemonSet{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       appsv1.DaemonSetSpec{Template: sensitivePodTemplateSpec()},
			}
			RedactDaemonSet(daemonSet)
			return daemonSet.ObjectMeta, daemonSet.Spec.Template.Spec
		}},
		{"ReplicaSet", func() (metav1.ObjectMeta, corev1.PodSpec) {
			replicaSet := &appsv1.ReplicaSet{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       appsv1.ReplicaSetSpec{Template: sensitivePodTemplateSpec()},
			}
			RedactReplicaSet(replicaSet)
			return replicaSet.ObjectMeta, replicaSet.Spec.Template.Spec
		}},
		{"StatefulSet", func() (metav1.ObjectMeta, corev1.PodSpec) {
			statefulSet := &appsv1.StatefulSet{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       appsv1.StatefulSetSpec{Template: sensitivePodTemplateSpec()},
			}
			RedactStatefulSet(statefulSet)
			return statefulSet.ObjectMeta, statefulSet.Spec.Template.Spec
		}},
		{"Job", func() (metav1.ObjectMeta, corev1.PodSpec) {
			job := &batchv1.Job{
				ObjectMeta: sensitiveObjectMeta(),
				Spec:       batchv1.JobSpec{Template: sensitivePodTemplateSpec()},
			}
			RedactJob(job)
			return job.ObjectMeta, job.Spec.Template.Spec
		}},
		{"CronJob", func() (metav1.ObjectMeta, corev1.PodSpec) {
			cronJob := &batchv1.CronJob{
				ObjectMeta: sensitiveObjectMeta(),
				Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{Template: sensitivePodTemplateSpec()},
				}},
			}
			RedactCronJob(cronJob)
			return cronJob.ObjectMeta, cronJob.Spec.JobTemplate.Spec.Template.Spec
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, spec := tt.redact()
			assertObjectMetaRedacted(t, meta)
			assertPodSpecRedacted(t, spec)
		})
	}
}

func TestRedactReplicationControllerWithoutTemplate(t *testing.T) {
	assert.NotPanics(t, func() { RedactReplicationController(&corev1.ReplicationController{}) })
}

func TestRedactControllerRevision(t *testing.T) {
	t.Run("redacts the embedded pod template", func(t *testing.T) {
		data, err := json.Marshal(map[string]interface{}{
			"spec": map[string]interface{}{"template": sensitivePodTemplateSpec()},
		})
		require.NoError(t, err)
		revision := &appsv1.ControllerRevision{ObjectMeta: sensitiveObjectMeta(), Data: runtime.RawExtension{Raw: data}}

		RedactControllerRevision(revision)

		assertObjectMetaRedacted(t, revision.ObjectMeta)
		assert.NotContains(t, string(revision.Data.Raw), secret)
		assert.Contains(t, string(revision.Data.Raw), "DB_PASSWORD")
	})

	t.Run("masks data that is not JSON", func(t *testing.T) {
		revision := &appsv1.ControllerRevision{Data: runtime.RawExtension{Raw: []byte("not json " + secret)}}

		RedactControllerRevision(revision)

		assert.JSONEq(t, `"`+RedactedValue+`"`, string(revision.Data.Raw))
	})
}

func TestRedactUnstructured(t *testing.T) {
	// e.g. an Argo Rollout, whose pod template is not known to the typed client.
	rollout := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{lastAppliedConfigAnnotation: secret},
		},
		"spec": map[string]interface{}{"template": map[string]interface{}{"spec": map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{
				"name":    "main",
				"command": []interface{}{"run"},
				"args":    []interface{}{"--token=" + secret},
				"env": []interface{}{
					map[string]interface{}{"name": "TOKEN", "value": secret},
					map[string]interface{}{"name": "FROM_SECRET", "valueFrom": map[string]interface{}{}},
				},
			}},
		}}},
	}

	RedactUnstructured(rollout)

	raw, err := json.Marshal(rollout)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret)
	container := rollout["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, []interface{}{RedactedValue}, container["command"])
	assert.Equal(t, []interface{}{RedactedValue}, container["args"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "TOKEN", "value": RedactedValue},
		map[string]interface{}{"name": "FROM_SECRET", "valueFrom": map[string]interface{}{}},
	}, container["env"])
}

func TestRedactUnstructuredLeavesOtherObjectsUntouched(t *testing.T) {
	configMap := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "cm"},
		"data":     map[string]interface{}{"args": "kept", "env": "kept"},
	}
	want := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "cm"},
		"data":     map[string]interface{}{"args": "kept", "env": "kept"},
	}

	RedactUnstructured(configMap)

	assert.Equal(t, want, configMap)
}

func TestRedactJSON(t *testing.T) {
	redacted, err := RedactJSON([]byte(`{"spec":{"containers":[{"name":"main","env":[{"name":"TOKEN","value":"` + secret + `"}]}]}}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"spec":{"containers":[{"name":"main","env":[{"name":"TOKEN","value":"`+RedactedValue+`"}]}]}}`, string(redacted))

	_, err = RedactJSON([]byte("not json"))
	assert.Error(t, err)
}

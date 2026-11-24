// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package kubernetes

import "encoding/json"

// RedactUnstructured applies the same redaction as RedactPod and friends to an
// object whose type is not known in advance (custom resources, raw JSON).
// Since the pod spec can be nested anywhere, any containers, initContainers or
// ephemeralContainers list found in the object is redacted, as well as any
// last-applied-configuration annotation.
func RedactUnstructured(object map[string]interface{}) {
	redactUnstructuredNode(object)
}

// RedactJSON redacts a JSON-encoded object with RedactUnstructured.
func RedactJSON(data []byte) ([]byte, error) {
	var object interface{}
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	redactUnstructuredNode(object)
	return json.Marshal(object)
}

func redactUnstructuredNode(node interface{}) {
	switch value := node.(type) {
	case map[string]interface{}:
		for key, child := range value {
			switch key {
			case "containers", "initContainers", "ephemeralContainers":
				redactUnstructuredContainers(child)
			case "annotations":
				redactUnstructuredAnnotations(child)
			}
			redactUnstructuredNode(child)
		}
	case []interface{}:
		for _, child := range value {
			redactUnstructuredNode(child)
		}
	}
}

func redactUnstructuredContainers(node interface{}) {
	containers, _ := node.([]interface{})
	for _, item := range containers {
		container, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		maskAllUnstructured(container["command"])
		maskAllUnstructured(container["args"])
		env, _ := container["env"].([]interface{})
		for _, item := range env {
			if envVar, ok := item.(map[string]interface{}); ok && envVar["value"] != nil {
				envVar["value"] = RedactedValue
			}
		}
	}
}

func redactUnstructuredAnnotations(node interface{}) {
	annotations, _ := node.(map[string]interface{})
	if _, found := annotations[lastAppliedConfigAnnotation]; found {
		annotations[lastAppliedConfigAnnotation] = RedactedValue
	}
}

func maskAllUnstructured(node interface{}) {
	values, _ := node.([]interface{})
	for i := range values {
		values[i] = RedactedValue
	}
}

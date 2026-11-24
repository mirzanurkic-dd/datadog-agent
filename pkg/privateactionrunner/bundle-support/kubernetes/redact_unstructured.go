// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package kubernetes

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/DataDog/datadog-agent/pkg/redact"
)

// RedactUnstructured applies the Agent's custom-resource scrubbing rules and
// sensitive metadata rules, including metadata in embedded templates.
func RedactUnstructured(object map[string]interface{}) {
	redact.ScrubCRManifest(&unstructured.Unstructured{Object: object}, sensitiveValuesScrubber)
	redactUnstructuredMetadata(object)
}

// RedactJSON redacts a JSON-encoded object with RedactUnstructured.
func RedactJSON(data []byte) ([]byte, error) {
	var object interface{}
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	redactJSONNode(object)
	return json.Marshal(object)
}

func redactJSONNode(node interface{}) {
	switch value := node.(type) {
	case map[string]interface{}:
		RedactUnstructured(value)
	case []interface{}:
		for _, child := range value {
			redactJSONNode(child)
		}
	}
}

func redactUnstructuredMetadata(node interface{}) {
	switch value := node.(type) {
	case map[string]interface{}:
		object := &unstructured.Unstructured{Object: value}
		meta := metav1.ObjectMeta{Annotations: object.GetAnnotations(), Labels: object.GetLabels()}
		redactObjectMeta(&meta)
		if meta.Annotations != nil {
			object.SetAnnotations(meta.Annotations)
		}
		if meta.Labels != nil {
			object.SetLabels(meta.Labels)
		}
		for _, child := range value {
			redactUnstructuredMetadata(child)
		}
	case []interface{}:
		for _, child := range value {
			redactUnstructuredMetadata(child)
		}
	}
}

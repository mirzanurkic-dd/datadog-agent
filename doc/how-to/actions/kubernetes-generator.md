# Generate Kubernetes private actions

Generate typed Kubernetes handlers and entrypoints using the repository's pinned
SDK sources:

```sh
bazel run //tools/privateactionrunner/kubernetes-generator
bazel run //tools/privateactionrunner/kubernetes-generator -- --bundle=core
bazel run //tools/privateactionrunner/kubernetes-generator -- --check
```

Edit `tools/privateactionrunner/kubernetes-generator/config.yaml` to select
resources and API versions. Edit the templates to change generated handlers.
Handwritten `New…Handler` constructors are registered alongside generated actions.
Generation replaces and removes `*.gen.go` files only in selected bundles;
`--check` reports stale files without modifying them. Use `--out=/tmp/kubernetes-actions`
to inspect output separately.

## Redacting sensitive values

When `private_action_runner.kubernetes_redact_sensitive_values` is enabled (the
default), actions returning objects that embed a pod spec mask container env
values, command and args, plus the `kubectl.kubernetes.io/last-applied-configuration`
annotation. Each such action does it explicitly, with the `support.Redact…`
helpers of `pkg/privateactionrunner/bundle-support/kubernetes`:

```go
if h.redactSensitiveValues {
	support.RedactPod(response)
}
```

- List a resource under `redactedResources` in `config.yaml` to generate its
  get, list, create, update and patch actions with this redaction. Every
  resource embedding a pod spec must be listed.
- A handwritten action returning such an object declares its constructor as
  `New…Handler(redactSensitiveValues bool)` and calls the matching helper; the
  generated entrypoint then passes it the setting. Handwritten constructors take
  no other parameters.
- Untyped objects (custom resources, raw JSON) use `support.RedactUnstructured`
  or `support.RedactJSON`.

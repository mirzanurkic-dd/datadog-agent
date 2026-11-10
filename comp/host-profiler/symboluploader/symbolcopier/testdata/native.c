// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Native fixture for streaming symbol export tests. It is never executed.

int native_counter = 1;

static int native_static(int value) { return value * 3 + native_counter; }

int native_exported(int value) { return native_static(value) + 1; }

#ifndef NATIVE_LIBRARY
int main(int argc, char **argv) {
    (void)argv;
    return native_exported(argc);
}
#endif

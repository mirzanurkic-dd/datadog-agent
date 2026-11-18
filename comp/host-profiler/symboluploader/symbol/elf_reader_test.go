// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package symbol

import (
	"io"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestSymbolReaderSelectsSource(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	require.NoError(t, err)
	elfData, err := os.ReadFile(executable)
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		separate Source
		expected string
	}{
		{"memory_vdso", SourceNone, "original"},
		{"better_separate_debug", SourceDebugInfo, "separate"},
		{"inferior_separate_symbols", SourceDynamicSymbolTable, "original"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newWrapper := func() *elfWrapper {
				file, err := (fstest.MapFS{"elf": {Data: elfData}}).Open("elf")
				require.NoError(t, err)
				elfFile, err := pfelf.NewFileFromFS(file)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, elfFile.Close()) })
				return &elfWrapper{elfFile: elfFile}
			}
			e := &Elf{elfWrapperWithSource: elfWrapperWithSource{wrapper: newWrapper(), symbolSource: SourceSymbolTable}}
			if tc.separate != SourceNone {
				e.separateSymbols = &elfWrapperWithSource{wrapper: newWrapper(), symbolSource: tc.separate}
			}
			want := e.wrapper
			if tc.expected == "separate" {
				want = e.separateSymbols.wrapper
			}
			reader, size, err := e.SymbolReader()
			require.NoError(t, err)
			require.Same(t, want.elfFile.Underlying(), reader)
			require.Equal(t, int64(len(elfData)), size)
			data, err := io.ReadAll(io.NewSectionReader(reader, 0, size))
			require.NoError(t, err)
			require.Equal(t, elfData, data)
		})
	}
}

func TestSymbolReaderUsesOpenFileNotPath(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	require.NoError(t, err)
	elfData, err := os.ReadFile(executable)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "source")
	require.NoError(t, err)
	defer file.Close()
	_, err = file.Write(elfData)
	require.NoError(t, err)
	elfFile, err := pfelf.NewFileFromFS(file)
	require.NoError(t, err)
	defer elfFile.Close()
	require.NoError(t, os.Remove(file.Name()))
	e := &Elf{elfWrapperWithSource: elfWrapperWithSource{wrapper: &elfWrapper{elfFile: elfFile, filePath: file.Name()}}}
	reader, size, err := e.SymbolReader()
	require.NoError(t, err)
	data, err := io.ReadAll(io.NewSectionReader(reader, 0, size))
	require.NoError(t, err)
	require.Equal(t, elfData, data)
	require.NoError(t, file.Close())
	_, _, err = e.SymbolReader()
	require.Error(t, err)
}

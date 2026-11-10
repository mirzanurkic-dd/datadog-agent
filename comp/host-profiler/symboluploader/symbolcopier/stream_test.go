// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package symbolcopier_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/bazelbuild/rules_go/go/runfiles"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbol"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbolcopier"
	elf "github.com/DataDog/datadog-agent/pkg/util/safeelf"
)

// Native fixtures (testdata/BUILD.bazel) cover the C toolchain layouts that the
// Go fixtures do not: an executable with DWARF, a stripped executable with only dynamic
// symbols, and a shared object.
func TestNativeSymbolStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    string
		source symbol.Source
		symbol string
	}{
		{"debug", "NATIVE_DEBUG", symbol.SourceDebugInfo, "native_static"},
		{"dynamic_symbols", "NATIVE_DYNSYM", symbol.SourceDynamicSymbolTable, "native_exported"},
		{"shared_debug", "NATIVE_SHARED_DEBUG", symbol.SourceDebugInfo, "native_static"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := runfiles.Rlocation(os.Getenv(tc.env))
			require.NoError(t, err)
			e, err := symbol.NewElfFromDisk(path)
			require.NoError(t, err)
			defer e.Close()
			require.Equal(t, tc.source, e.SymbolSource())
			var keep []symbol.SectionInfo
			if tc.source == symbol.SourceDynamicSymbolTable {
				keep = e.GetSectionsRequiredForDynamicSymbols()
			}

			input, err := os.Open(path)
			require.NoError(t, err)
			defer input.Close()
			stat, err := input.Stat()
			require.NoError(t, err)
			stream, err := symbolcopier.NewSymbolStream(t.Context(), input, stat.Size(), nil, keep)
			require.NoError(t, err)
			var out bytes.Buffer
			require.NoError(t, stream.Write(t.Context(), &out))
			require.EqualValues(t, stream.Size(), out.Len())

			original, err := elf.Open(path)
			require.NoError(t, err)
			defer original.Close()
			output, err := elf.NewFile(bytes.NewReader(out.Bytes()))
			require.NoError(t, err)
			defer output.Close()

			// Identity and section slots are kept; code bytes are not.
			require.Equal(t, original.FileHeader, output.FileHeader)
			require.Len(t, output.Sections, len(original.Sections))
			text := output.Section(".text")
			require.NotNil(t, text)
			require.Equal(t, elf.SHT_NOBITS, text.Type)
			require.Equal(t, original.Section(".text").Addr, text.Addr)

			// Build IDs live in notes.
			require.NotNil(t, output.Section(".note.gnu.build-id"))
			for _, want := range original.Sections {
				if want.Type != elf.SHT_NOTE {
					continue
				}
				wantData, err := want.Data()
				require.NoError(t, err)
				gotData, err := output.Section(want.Name).Data()
				require.NoError(t, err)
				require.Equal(t, wantData, gotData, want.Name)
			}

			if tc.source == symbol.SourceDynamicSymbolTable {
				want, err := original.DynamicSymbols()
				require.NoError(t, err)
				got, err := output.DynamicSymbols()
				require.NoError(t, err)
				// GNU version tables are omitted, so compare the symbols themselves.
				require.Len(t, got, len(want))
				for i := range want {
					require.Equal(t, [5]any{want[i].Name, want[i].Info, want[i].Section, want[i].Value, want[i].Size},
						[5]any{got[i].Name, got[i].Info, got[i].Section, got[i].Value, got[i].Size})
				}
				require.Contains(t, symbolNames(got), tc.symbol)
				return
			}

			want, err := original.Symbols()
			require.NoError(t, err)
			got, err := output.Symbols()
			require.NoError(t, err)
			require.Equal(t, want, got)
			require.Contains(t, symbolNames(got), tc.symbol)
			for _, section := range original.Sections {
				if section.Type == elf.SHT_NOBITS || !strings.HasPrefix(section.Name, ".debug_") {
					continue
				}
				wantData, err := section.Data()
				require.NoError(t, err)
				gotData, err := output.Section(section.Name).Data()
				require.NoError(t, err)
				require.Equal(t, wantData, gotData, section.Name)
			}
			dwarf, err := output.DWARF()
			require.NoError(t, err)
			entry, err := dwarf.Reader().Next()
			require.NoError(t, err)
			require.NotNil(t, entry, "DWARF must contain a compile unit")
		})
	}
}

func symbolNames(symbols []elf.Symbol) []string {
	names := make([]string, 0, len(symbols))
	for _, sym := range symbols {
		names = append(names, sym.Name)
	}
	return names
}

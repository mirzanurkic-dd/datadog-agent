// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package symboluploader

import (
	"bytes"
	"context"
	"debug/gosym"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/DataDog/jsonapi"
	"github.com/DataDog/zstd"
	"github.com/bazelbuild/rules_go/go/runfiles"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"

	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbol"
	"github.com/DataDog/datadog-agent/pkg/util/elfstream"
	elf "github.com/DataDog/datadog-agent/pkg/util/safeelf"
)

const (
	envBazelGoBinary = "GO_BINARY_RLOCATION"
	envBazelGoRoot   = "GO_ROOT_RLOCATION"
)

var objcopyZstdSupport = CheckObjcopyZstdSupport(context.Background())

// dummyProcess implements pfelf.Process for testing purposes
type dummyProcess struct {
	pid libpf.PID
}

func (d *dummyProcess) PID() libpf.PID {
	return d.pid
}

func (d *dummyProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (d *dummyProcess) IterateMappings(_ func(m process.RawMapping) bool) (uint32, error) {
	return 0, errors.New("not implemented")
}

func (d *dummyProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (d *dummyProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (d *dummyProcess) GetMappingFileLastModified(_ *process.RawMapping) int64 {
	return 0
}

func (d *dummyProcess) CalculateMappingFileID(m *process.RawMapping) (libpf.FileID, error) {
	return libpf.FileIDFromExecutableFile(m.Path)
}

func (d *dummyProcess) OpenMappingFile(m *process.RawMapping) (fs.File, error) {
	return os.Open(m.Path)
}

func (d *dummyProcess) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (d *dummyProcess) Close() error {
	return nil
}

func (d *dummyProcess) GetExe() (libpf.String, error) {
	str, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", d.pid))
	if err != nil {
		return libpf.NullString, err
	}
	return libpf.Intern(str), nil
}

func (d *dummyProcess) GetProcessMeta(_ []process.MetaEnricher) process.Meta {
	return process.Meta{}
}

func newExecutableMetadata(t *testing.T, filePath string) *reporter.ExecutableMetadata {
	ef, err := pfelf.Open(filePath)
	require.NoError(t, err)
	defer ef.Close()

	goBuildID, err := ef.GetGoBuildID()
	require.NoError(t, err)
	fileID, err := libpf.FileIDFromExecutableFile(filePath)
	require.NoError(t, err)
	mf := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
		FileID:     fileID,
		FileName:   libpf.Intern(path.Base(filePath)),
		GnuBuildID: "",
		GoBuildID:  goBuildID,
	})
	pr := &dummyProcess{pid: libpf.PID(os.Getpid())}
	m := &process.RawMapping{
		Path: filePath,
	}
	return &reporter.ExecutableMetadata{
		MappingFile:       mf,
		Process:           pr,
		Mapping:           m,
		DebuglinkFileName: "",
	}
}

func findSymbol(f *elf.File, name string) *elf.Symbol {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	for _, sym := range syms {
		if sym.Name == name {
			return &sym
		}
	}
	return nil
}

func findDynamicSymbol(f *elf.File, name string) *elf.Symbol {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil
	}
	for _, sym := range syms {
		if sym.Name == name {
			return &sym
		}
	}
	return nil
}

func checkGoPCLnTab(t *testing.T, f *elf.File, checkGoFunc bool) {
	section := f.Section(".gopclntab")
	require.NotNil(t, section)
	require.Equal(t, elf.SHT_PROGBITS, section.Type)
	data, err := section.Data()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(data), 16)

	var quantum byte
	switch runtime.GOARCH {
	case "amd64":
		quantum = 0x1
	case "arm64":
		quantum = 0x4
	}

	expectedHeader := []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
	assert.Equal(t, expectedHeader, data[:8])

	if checkGoFunc {
		require.NotNil(t, findSymbol(f, "go:func.*"))
	}
}

func checkRequest(t *testing.T, req *http.Request, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedContentEncoding string) {
	require.Equal(t, "POST", req.Method)
	if expectedContentEncoding != "" {
		require.Equal(t, expectedContentEncoding, req.Header.Get("Content-Encoding"))
	} else {
		require.NotContains(t, req.Header, "Content-Encoding")
	}

	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	require.NoError(t, err)
	boundary, ok := params["boundary"]
	require.True(t, ok)

	var reader io.ReadCloser
	if req.Header.Get("Content-Encoding") == "zstd" {
		reader = zstd.NewReader(req.Body)
		defer reader.Close()
	} else {
		reader = req.Body
	}

	mr := multipart.NewReader(reader, boundary)
	form, err := mr.ReadForm(1 << 20) // 1 MiB
	require.NoError(t, err)
	fhs, ok := form.File["elf_symbol_file"]
	require.True(t, ok)
	f, err := fhs[0].Open()
	require.NoError(t, err)
	defer f.Close()

	event, ok := form.File["event"]
	require.True(t, ok)
	e, err := event[0].Open()
	require.NoError(t, err)
	defer e.Close()

	// unmarshal json into map[string]string
	// check that the symbol source is correct
	result := make(map[string]string)
	err = json.NewDecoder(e).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, expectedSymbolSource.String(), result["symbol_source"])

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	// Streaming compresses only the ELF file part.
	if bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		data, err = zstd.Decompress(nil, data)
		require.NoError(t, err)
	}
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	defer elfFile.Close()

	if expectedGoPCLnTab || expectedSymbolSource == symbol.SourceGoPCLnTab {
		checkGoPCLnTab(t, elfFile, true)
	}

	switch expectedSymbolSource {
	case symbol.SourceDynamicSymbolTable:
		require.NotNil(t, findDynamicSymbol(elfFile, "_cgo_panic"))
	case symbol.SourceSymbolTable:
		require.NotNil(t, findSymbol(elfFile, "main.main"))
	case symbol.SourceDebugInfo:
		require.True(t, hasDWARFData(elfFile))
	}
}

func hasDWARFData(elfFile *elf.File) bool {
	hasBuildID := false
	hasDebugStr := false
	for _, section := range elfFile.Sections {
		// NOBITS indicates that the section is actually empty, regardless of the size in the
		// section header.
		if section.Type == elf.SHT_NOBITS {
			continue
		}

		if section.Name == ".note.gnu.build-id" {
			hasBuildID = true
		}

		if section.Name == ".debug_str" || section.Name == ".zdebug_str" ||
			section.Name == ".debug_str.dwo" {
			hasDebugStr = section.Size > 0
		}

		// Some files have suspicious near-empty, partially stripped sections; consider them as not
		// having DWARF data.
		// The simplest binary gcc 10 can generate ("return 0") has >= 48 bytes for each section.
		// Let's not worry about executables that may not verify this, as they would not be of
		// interest to us.
		if section.Size < 32 {
			continue
		}

		if section.Name == ".debug_info" || section.Name == ".zdebug_info" {
			return true
		}
	}

	// Some alternate debug files only have a .debug_str section. For these we want to return true.
	// Use the absence of program headers and presence of a Build ID as heuristic to identify
	// alternate debug files.
	return len(elfFile.Progs) == 0 && hasBuildID && hasDebugStr
}

var testEndpoints = []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

type uploaderOpts struct {
	uploadDynamicSymbols           bool
	uploadGoPCLnTab                bool
	disableDebugSectionCompression bool
	streamSymbols                  bool
}

func newTestUploader(ctx context.Context, opts uploaderOpts) (*DatadogSymbolUploader, error) {
	endpoints := make([]SymbolEndpoint, 0, len(testEndpoints))
	for _, e := range testEndpoints {
		endpoints = append(endpoints, SymbolEndpoint{
			Site:   e,
			APIKey: "api_key",
		})
	}

	cfg := &SymbolUploaderConfig{
		SymbolUploaderOptions: SymbolUploaderOptions{
			Enabled:              true,
			UploadDynamicSymbols: opts.uploadDynamicSymbols,
			UploadGoPCLnTab:      opts.uploadGoPCLnTab,
			StreamSymbols:        opts.streamSymbols,
			SymbolQueryInterval:  0,
			SymbolEndpoints:      endpoints,
		},
		DisableDebugSectionCompression: opts.disableDebugSectionCompression,
	}
	return NewDatadogSymbolUploader(ctx, cfg)
}

type buildOptions struct {
	dynsym            bool
	symtab            bool
	debugInfos        bool
	corruptGoPCLnTab  bool
	uncompressedDWARF bool
}

func resolveRunfile(t *testing.T, loc string) string {
	path, err := runfiles.Rlocation(loc)
	require.NoErrorf(t, err, "resolving runfile %q", loc)
	return path
}

func buildGo(t *testing.T, tmpDir, buildID string, opts buildOptions) string {
	goBinary := "go"
	var goEnv []string

	// Use Bazel-provided Go toolchain if available
	if loc := os.Getenv(envBazelGoBinary); loc != "" {
		goBinary = resolveRunfile(t, loc)

		rootLoc := os.Getenv(envBazelGoRoot)
		require.NotEmpty(t, rootLoc, "%s must be set when %s is set", envBazelGoRoot, envBazelGoBinary)
		goRoot := filepath.Dir(resolveRunfile(t, rootLoc))

		// Keep the Go command's caches inside the test temp directory to minimize side-effects.
		goCacheDir := filepath.Join(tmpDir, "go-cache")
		goPathDir := filepath.Join(tmpDir, "gopath")
		require.NoError(t, os.MkdirAll(goCacheDir, 0o755))
		require.NoError(t, os.MkdirAll(goPathDir, 0o755))

		goEnv = append(goEnv,
			"GOTOOLCHAIN=local", // Prevent toolchain downloading
			"GOROOT="+goRoot,
			"GOCACHE="+goCacheDir,
			"GOPATH="+goPathDir,
			"GOMODCACHE="+filepath.Join(goPathDir, "pkg", "mod"),
		)
	}

	f, err := os.CreateTemp(tmpDir, "helloworld")
	require.NoError(t, err)
	defer f.Close()

	exe := f.Name()
	args := []string{"build", "-o", exe}
	ldflags := "-ldflags=-buildid=" + buildID + " "
	if opts.dynsym {
		ldflags += "-linkmode=external "
	}
	if opts.uncompressedDWARF {
		ldflags += "-compressdwarf=false "
	}

	args = append(args, ldflags, "./testdata/helloworld.go")
	cmd := exec.CommandContext(t.Context(), goBinary, args...) // #nosec G204
	cmd.Env = append(cmd.Environ(), goEnv...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)

	args = []string{"-R", ".note.gnu.build-id"}
	if opts.debugInfos && !opts.symtab {
		t.Errorf("Cannot have debug infos without symtab")
	}

	if !opts.debugInfos {
		if opts.symtab {
			args = append(args, "-g")
		} else {
			args = append(args, "-S")
		}
	}
	if opts.corruptGoPCLnTab {
		// Remove the pclntab section
		args = append(args, "-R", ".gopclntab")
	}
	args = append(args, exe)
	cmd = exec.CommandContext(t.Context(), "objcopy", args...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "failed to strip test binary with `%v`: %s\n%s", cmd.Args, err, out)

	return exe
}

func buildSymbolQueryResponse(t *testing.T, buildID string, symbolSource symbol.Source) string {
	var symbolFiles []SymbolFile
	if symbolSource != symbol.SourceNone {
		symbolFiles = []SymbolFile{
			{
				ID:           "1",
				BuildID:      buildID,
				SymbolSource: symbolSource.String(),
				BuildIDType:  "go_build_id",
			},
		}
	}
	r, err := jsonapi.Marshal(&symbolFiles)
	require.NoError(t, err)
	return string(r)
}

func registerResponders(t *testing.T, buildID string) []chan *http.Request {
	channels := make([]chan *http.Request, 0, len(testEndpoints))
	symbolSources := []symbol.Source{symbol.SourceNone, symbol.SourceDynamicSymbolTable, symbol.SourceSymbolTable, symbol.SourceGoPCLnTab, symbol.SourceDebugInfo}
	for i, e := range testEndpoints {
		c := make(chan *http.Request, 1)
		channels = append(channels, c)
		httpmock.RegisterResponder("POST", buildSymbolQueryURL(e),
			httpmock.NewStringResponder(200, buildSymbolQueryResponse(t, buildID, symbolSources[i])))
		httpmock.RegisterResponder("POST", buildSourcemapIntakeURL(e),
			func(req *http.Request) (*http.Response, error) {
				// Read request body before sending response otherwise client will receive the response before having sent all the data
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				req.Body = io.NopCloser(bytes.NewReader(b))
				c <- req
				return httpmock.NewStringResponse(200, ""), nil
			})
	}
	return channels
}

// captureUploadReports routes slog.Default to a JSON buffer, so tests can
// assert on symbol upload reports.
func captureUploadReports(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("logs:\n%s", buf.String())
		}
	})
	return buf
}

func uploadReportCounts(t *testing.T, buf *bytes.Buffer) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for line := range bytes.Lines(buf.Bytes()) {
		var record map[string]any
		require.NoError(t, json.Unmarshal(line, &record))
		if record["msg"] != "Symbol Upload Report" {
			continue
		}
		for key, value := range record {
			reason, ok := strings.CutPrefix(key, "status_by_reason.")
			if !ok {
				continue
			}
			if reason, ok = strings.CutSuffix(reason, ".count"); ok {
				count, isNumber := value.(float64)
				require.True(t, isNumber, "non-numeric count for %s", key)
				counts[reason] += int(count)
			}
		}
	}
	return counts
}

//nolint:tparallel
func TestSymbolUpload(t *testing.T) {
	t.Parallel()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	slog.SetLogLoggerLevel(slog.LevelDebug)
	buildID := "some_go_build_id"
	channels := registerResponders(t, buildID)

	checkUploadsWithEncoding := func(t *testing.T, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedUploads []bool, expectedEncoding string) {
		callCountInfo := httpmock.GetCallCountInfo()
		for i, e := range testEndpoints {
			assert.Equal(t, 1, callCountInfo["POST "+buildSymbolQueryURL(e)])
			if expectedUploads[i] {
				assert.Equal(t, 1, callCountInfo["POST "+buildSourcemapIntakeURL(e)])
				req := <-channels[i]
				checkRequest(t, req, expectedSymbolSource, expectedGoPCLnTab, expectedEncoding)
			} else {
				assert.Equal(t, 0, callCountInfo["POST "+buildSourcemapIntakeURL(e)])
			}
		}
	}

	checkUploads := func(t *testing.T, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedUploads []bool) {
		expectedEncoding := ""
		if !objcopyZstdSupport {
			expectedEncoding = "zstd"
		}
		checkUploadsWithEncoding(t, expectedSymbolSource, expectedGoPCLnTab, expectedUploads, expectedEncoding)
	}

	goExeNoSymbols := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: false, symtab: false, debugInfos: false})
	goExeyDynsym := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: false, debugInfos: false})
	goExeSymtab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: false})
	goExeDebugInfos := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: true})
	goExeyDynsymCorruptGoPCLnTab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: false, debugInfos: false, corruptGoPCLnTab: true})
	goExeDebugInfosCorruptGoPCLnTab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: true, corruptGoPCLnTab: true})

	t.Run("No symbol upload if no symbols", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeNoSymbols))
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
		require.Equal(t, map[string]int{reasonNoDebugSymbols: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Upload if symtab", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		execMeta := newExecutableMetadata(t, goExeSymtab)
		uploader.UploadSymbols(execMeta)
		uploader.Stop()

		checkUploads(t, symbol.SourceSymbolTable, false, []bool{true, true, false, false, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))

		uploader.UploadSymbols(execMeta)
		uploader.reporter.flush()
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1, reasonAlreadyUploaded: 1},
			uploadReportCounts(t, reports))
	})

	t.Run("Upload if debug info", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfos))
		uploader.Stop()

		checkUploads(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})

	t.Run("No upload if dynamic symbols", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsym))
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
		require.Equal(t, map[string]int{reasonNoDebugSymbols: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Upload if dynamic symbols when enabled", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{uploadDynamicSymbols: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsym))
		uploader.Stop()

		checkUploads(t, symbol.SourceDynamicSymbolTable, false, []bool{true, false, false, false, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Upload pclntab when enabled", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeNoSymbols))
		uploader.Stop()

		checkUploads(t, symbol.SourceGoPCLnTab, true, []bool{true, true, true, false, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Upload debug infos if pclntab is corrupted", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfosCorruptGoPCLnTab))
		uploader.Stop()

		checkUploads(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Upload dynamic symbols if pclntab is corrupted and only dyn sym when enabled", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{uploadDynamicSymbols: true, uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsymCorruptGoPCLnTab))
		uploader.Stop()

		checkUploads(t, symbol.SourceDynamicSymbolTable, false, []bool{true, false, false, false, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})

	t.Run("No symbol upload if pclntab is corrupted and only dynsym", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsymCorruptGoPCLnTab))
		uploader.Stop()

		checkUploads(t, symbol.SourceNone, false, []bool{false, false, false, false, false})
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonGoPCLnTabError: 1}, uploadReportCounts(t, reports))
	})

	t.Run("Report skipped upload when no endpoint needs symbols", func(t *testing.T) {
		tests := []struct {
			name       string
			backend    SymbolQueryResult
			wantCounts map[string]int
		}{
			{"existing symbols", SymbolQueryResult{SymbolSource: symbol.SourceDebugInfo}, map[string]int{reasonExistingSymbols: 1}},
			{"query error", SymbolQueryResult{Err: errors.New("query failed")}, map[string]int{}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				reports := captureUploadReports(t)
				uploader, err := newTestUploader(t.Context(), uploaderOpts{})
				require.NoError(t, err)
				e, err := symbol.NewElfFromDisk(goExeSymtab)
				require.NoError(t, err)

				uploader.uploadWorker(t.Context(), ElfWithBackendSources{Elf: e, BackendSymbolSources: []SymbolQueryResult{tt.backend}})
				uploader.reporter.flush()

				require.Equal(t, tt.wantCounts, uploadReportCounts(t, reports))
			})
		}
	})

	t.Run("Upload compressed request when debug section compression is disabled", func(t *testing.T) {
		reports := captureUploadReports(t)
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(t.Context(), uploaderOpts{disableDebugSectionCompression: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfos))
		uploader.Stop()

		checkUploadsWithEncoding(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false}, "zstd")
		require.Equal(t, map[string]int{reasonQueried: len(testEndpoints), reasonUploaded: 1}, uploadReportCounts(t, reports))
	})
}

// memProcess serves its mappings from memory rather than from files, as
// systemProcess does for the vdso.
type memProcess struct {
	dummyProcess
	mappings fstest.MapFS
}

func (p *memProcess) OpenMappingFile(m *process.RawMapping) (fs.File, error) {
	return p.mappings.Open(m.Path)
}

func TestElfFromMemoryMapping(t *testing.T) {
	data, err := os.ReadFile(buildGo(t, t.TempDir(), "test", buildOptions{}))
	require.NoError(t, err)

	t.Run("vdso", func(t *testing.T) {
		pr := &memProcess{mappings: fstest.MapFS{process.VdsoPathName: {Data: data}}}
		m := &process.RawMapping{Path: process.VdsoPathName}
		e, err := symbol.NewElfFromMapping(m, "", "", libpf.FileID{}, pr)
		require.NoError(t, err)

		// The vdso has no backing file, so its content is dumped to a temporary file.
		assert.Empty(t, e.SymbolPathOnDisk())
		assert.Equal(t, int64(len(data)), e.GetSize())
		dump, err := e.DumpElfData()
		require.NoError(t, err)
		got, err := os.ReadFile(dump)
		require.NoError(t, err)
		assert.Equal(t, data, got)

		e.Close()
		_, err = os.Stat(dump)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("other mappings need a backing file", func(t *testing.T) {
		pr := &memProcess{mappings: fstest.MapFS{"helloworld": {Data: data}}}
		m := &process.RawMapping{Path: "helloworld"}
		_, err := symbol.NewElfFromMapping(m, "", "", libpf.FileID{}, pr)
		require.Error(t, err)
	})
}

// Verify that the symbol uploader transport has the same exported fields as http.DefaultTransport
// when HTTP/2 is disabled
func TestTransport(t *testing.T) {
	cfg := &SymbolUploaderConfig{
		SymbolUploaderOptions: SymbolUploaderOptions{
			Enabled:         true,
			UseHTTP2:        false, // This forces creation of custom transport
			SymbolEndpoints: []SymbolEndpoint{{Site: "test.com", APIKey: "key"}},
		},
		Version: "test",
	}

	uploader, err := NewDatadogSymbolUploader(t.Context(), cfg)
	require.NoError(t, err)

	customTransport, ok := uploader.client.Transport.(*http.Transport)
	require.True(t, ok, "Expected custom transport to be *http.Transport")

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok, "Expected http.DefaultTransport to be *http.Transport")

	// Use reflection to compare all exported fields
	customValue := reflect.ValueOf(customTransport).Elem()
	defaultValue := reflect.ValueOf(defaultTransport).Elem()
	customType := customValue.Type()

	for i := range customType.NumField() {
		field := customType.Field(i)
		if !field.IsExported() {
			continue
		}

		customFieldValue := customValue.Field(i)
		defaultFieldValue := defaultValue.Field(i)

		// Special handling for intentionally different fields
		switch field.Name {
		case "TLSNextProto":
			// TLSNextProto should be an empty map in custom transport to disable HTTP/2
			assert.NotNil(t, customFieldValue.Interface(), "TLSNextProto should not be nil")
			assert.Equal(t, 0, customFieldValue.Len(), "TLSNextProto should be empty map")
		case "ForceAttemptHTTP2":
			// ForceAttemptHTTP2 should be false in custom transport to disable HTTP/2
			assert.False(t, customFieldValue.Bool(), "ForceAttemptHTTP2 should be false to disable HTTP/2")
		case "TLSClientConfig":
			// TLSClientConfig should be nil in custom transport
			// The default transport might have a non-nil value if the default transport
			// was used in another test (for example through the default http client)
			assert.Nil(t, customFieldValue.Interface(), "TLSClientConfig should be nil")
		default:
			if customFieldValue.Kind() == reflect.Func {
				assert.Equal(t, defaultFieldValue.Pointer(), customFieldValue.Pointer(), "Function field %s should match", field.Name)
				continue
			}
			if !customFieldValue.CanInterface() || !defaultFieldValue.CanInterface() {
				assert.Failf(t, "Cannot compare field %s", field.Name)
				continue
			}
			assert.Equal(t, defaultFieldValue.Interface(), customFieldValue.Interface(),
				"Field %s should match default transport", field.Name)
		}
	}
}

func TestNewDatadogSymbolUploaderPropagatesReportConfig(t *testing.T) {
	tests := []struct {
		name         string
		report       ReportConfig
		wantInterval time.Duration
		wantMax      int
	}{
		{"explicit positive", ReportConfig{Interval: 30, MaxPathsPerReport: 7}, 30 * time.Second, 7},
		{"zero value", ReportConfig{}, DefaultReportInterval, DefaultReportMaxPathsPerReport},
		{"negative", ReportConfig{Interval: -1, MaxPathsPerReport: -1}, DefaultReportInterval, DefaultReportMaxPathsPerReport},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SymbolUploaderConfig{
				SymbolUploaderOptions: SymbolUploaderOptions{
					Enabled:         true,
					SymbolEndpoints: []SymbolEndpoint{{Site: "test.com", APIKey: "key"}},
					Report:          tt.report,
				},
				Version: "test",
			}

			uploader, err := NewDatadogSymbolUploader(t.Context(), cfg)
			require.NoError(t, err)

			require.Equal(t, tt.wantInterval, uploader.reporter.interval)
			require.Equal(t, tt.wantMax, uploader.reporter.infoRep.maxPaths)
			require.Equal(t, tt.wantMax, uploader.reporter.errRep.maxPaths)
		})
	}
}

type symbolUploadRoundTripFunc func(*http.Request) (*http.Response, error)

func (f symbolUploadRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStreamingSymbolUpload(t *testing.T) {
	// Environment changes are deliberately non-parallel. Fixture construction is
	// outside the diskless portion; only upload must work without tmpdir/objcopy.
	for _, tc := range []struct {
		name   string
		build  buildOptions
		goInfo bool
		source symbol.Source
	}{
		{"stripped_go", buildOptions{}, true, symbol.SourceGoPCLnTab},
		{"external_go", buildOptions{dynsym: true}, true, symbol.SourceGoPCLnTab},
		{"static_symbols", buildOptions{symtab: true}, false, symbol.SourceSymbolTable},
		{"dynamic_symbols", buildOptions{dynsym: true, corruptGoPCLnTab: true}, false, symbol.SourceDynamicSymbolTable},
		{"dwarf_and_go", buildOptions{dynsym: true, symtab: true, debugInfos: true}, true, symbol.SourceDebugInfo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exe := buildGo(t, t.TempDir(), "stream_test_build_id", tc.build)
			e, err := symbol.NewElfFromDisk(exe)
			require.NoError(t, err)
			defer e.Close()
			requests := make(chan *http.Request, 2)
			t.Run("diskless_upload", func(t *testing.T) {
				reports := captureUploadReports(t)
				t.Setenv("PATH", "")
				t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
				uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true, uploadGoPCLnTab: tc.goInfo, uploadDynamicSymbols: true})
				require.NoError(t, err, "streaming must not require objcopy")
				uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					data, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					req.Body = io.NopCloser(bytes.NewReader(data))
					requests <- req
					return httpmock.NewStringResponse(http.StatusOK, ""), nil
				})
				require.True(t, uploader.upload(t.Context(), e, []int{0, 1}), "streaming upload failed; see uploader log")
				uploader.reporter.flush()
				require.Equal(t, map[string]int{reasonUploaded: 1}, uploadReportCounts(t, reports))
			})
			if len(requests) != 2 {
				t.Fatal("diskless upload did not complete both destinations")
			}
			for range 2 {
				req := <-requests
				data, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				req.Body = io.NopCloser(bytes.NewReader(data))
				checkRequest(t, req, tc.source, tc.goInfo, "")
				_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
				require.NoError(t, err)
				part, err := multipart.NewReader(bytes.NewReader(data), params["boundary"]).NextPart()
				require.NoError(t, err)
				encoded, err := io.ReadAll(part)
				require.NoError(t, err)
				elfBytes, err := zstd.Decompress(nil, encoded)
				require.NoError(t, err)
				f, err := elf.NewFile(bytes.NewReader(elfBytes))
				require.NoError(t, err)
				defer f.Close()
				// Build IDs are read from note sections, so every note must survive.
				original, err := elf.Open(exe)
				require.NoError(t, err)
				defer original.Close()
				notes := 0
				for _, want := range original.Sections {
					if want.Type != elf.SHT_NOTE {
						continue
					}
					notes++
					got := f.Section(want.Name)
					require.NotNil(t, got, want.Name)
					wantData, err := want.Data()
					require.NoError(t, err)
					gotData, err := got.Data()
					require.NoError(t, err)
					require.Equal(t, wantData, gotData, want.Name)
				}
				require.Positive(t, notes, "fixture must carry build-ID notes")
				if tc.goInfo {
					pcln, err := f.Section(".gopclntab").Data()
					require.NoError(t, err)
					info, err := e.GoPCLnTab()
					require.NoError(t, err)
					table, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, info.TextStart.Address))
					require.NoError(t, err)
					main := table.LookupFunc("main.main")
					require.NotNil(t, main)
					file, line, _ := table.PCToLine(main.Entry)
					require.Contains(t, file, "helloworld.go")
					require.Positive(t, line)
				}
			}
		})
	}
}

func TestSymbolCompressionWindow(t *testing.T) {
	for _, tt := range []struct {
		size   int64
		window int
	}{
		{0, 128 * 1024},
		{1, 128 * 1024},
		{128*1024 - 1, 128 * 1024},
		{128 * 1024, 128 * 1024},
		{128*1024 + 1, 256 * 1024},
		{200 * 1024, 256 * 1024},
		{256 * 1024, 256 * 1024},
		{256*1024 + 1, 512 * 1024},
		{8*1024*1024 - 1, 8 * 1024 * 1024},
		{8 * 1024 * 1024, 8 * 1024 * 1024},
		{8*1024*1024 + 1, 8 * 1024 * 1024},
		{1 << 30, 8 * 1024 * 1024},
		{1<<63 - 1, 8 * 1024 * 1024},
	} {
		t.Run(strconv.FormatInt(tt.size, 10), func(t *testing.T) {
			require.Equal(t, tt.window, 1<<symbolCompressionWindowLog(tt.size))
		})
	}
}

// Streaming compresses the complete ELF once, without newly encoding DWARF.
func TestSymbolFileCompression(t *testing.T) {
	exe := buildGo(t, t.TempDir(), "whole_symbol_build_id", buildOptions{symtab: true, debugInfos: true, uncompressedDWARF: true})
	original, err := elf.Open(exe)
	require.NoError(t, err)
	defer original.Close()
	e, err := symbol.NewElfFromDisk(exe)
	require.NoError(t, err)
	defer e.Close()
	// Neither planning nor compression may require a spool or objcopy.
	t.Setenv("PATH", "")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
	uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
	require.NoError(t, err)
	var body []byte
	var contentType string
	uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Empty(t, req.Header.Get("Content-Encoding"))
		var err error
		body, err = io.ReadAll(req.Body)
		contentType = req.Header.Get("Content-Type")
		return httpmock.NewStringResponse(http.StatusOK, ""), err
	})
	require.True(t, uploader.upload(t.Context(), e, []int{0}))
	_, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(body, []byte("--"+params["boundary"]+"--\r\n")))
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	part, err := mr.NextPart()
	require.NoError(t, err)
	require.Equal(t, "elf_symbol_file", part.FormName())
	require.Equal(t, "elf_symbol_file", part.FileName())
	require.Empty(t, part.Header.Get("Content-Encoding"))
	encoded, err := io.ReadAll(part)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(encoded, []byte{0x28, 0xb5, 0x2f, 0xfd}))
	data, err := zstd.Decompress(nil, encoded)
	require.NoError(t, err)
	output, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	defer output.Close()
	require.Zero(t, output.Section(".debug_info").Flags&elf.SHF_COMPRESSED)
	for _, section := range original.Sections {
		if !strings.HasPrefix(section.Name, ".debug_") {
			continue
		}
		before, err := section.Data()
		require.NoError(t, err)
		after, err := output.Section(section.Name).Data()
		require.NoError(t, err)
		require.Equal(t, before, after, section.Name)
	}
	part, err = mr.NextPart()
	require.NoError(t, err)
	require.Equal(t, "event", part.FormName())
	var metadata symbolUploadRequestMetadata
	require.NoError(t, json.NewDecoder(part).Decode(&metadata))
	require.Equal(t, "elf_symbol_file", metadata.Type)
	_, err = mr.NextPart()
	require.ErrorIs(t, err, io.EOF)
}

func TestCompressedSymbolMultipartPerEndpoint(t *testing.T) {
	uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
	require.NoError(t, err)
	payload := bytes.Repeat([]byte("complete ELF bytes\x00"), 10000)
	uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Empty(t, req.Header.Get("Content-Encoding"))
		body, err := io.ReadAll(req.Body)
		_, params, parseErr := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if parseErr != nil {
			return nil, parseErr
		}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		part, parseErr := mr.NextPart()
		if parseErr != nil {
			return nil, parseErr
		}
		encoded, parseErr := io.ReadAll(part)
		if parseErr != nil {
			return nil, parseErr
		}
		decoded, parseErr := zstd.Decompress(nil, encoded)
		require.NoError(t, parseErr)
		require.Equal(t, payload, decoded)
		part, parseErr = mr.NextPart()
		require.NoError(t, parseErr)
		var metadata symbolUploadRequestMetadata
		require.NoError(t, json.NewDecoder(part).Decode(&metadata))
		require.Equal(t, "elf_symbol_file", metadata.Type)
		_, parseErr = mr.NextPart()
		require.ErrorIs(t, parseErr, io.EOF)
		return httpmock.NewStringResponse(http.StatusOK, ""), err
	})
	var calls atomic.Int32
	err = uploader.sendSymbolStream(t.Context(), int64(len(payload)), func(w io.Writer) error {
		calls.Add(1)
		_, err := w.Write(payload)
		return err
	}, &symbolUploadRequestMetadata{Type: "elf_symbol_file"}, []int{0, 1})
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load(), "each endpoint gets its own write of the ELF")
}

// A stalled or failing endpoint must not hold back or fail delivery to the others.
func TestStreamingEndpointsAreIndependent(t *testing.T) {
	for _, failure := range []string{"stalled", "rejected"} {
		t.Run(failure, func(t *testing.T) {
			uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
			require.NoError(t, err)
			healthy := make(chan error, 1)
			uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "a.com") {
					if failure == "rejected" {
						return httpmock.NewStringResponse(http.StatusInternalServerError, ""), nil
					}
					<-req.Context().Done() // Never reads the body.
					return nil, req.Context().Err()
				}
				_, err := io.Copy(io.Discard, req.Body)
				healthy <- err
				return httpmock.NewStringResponse(http.StatusOK, ""), err
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- uploader.sendSymbolStream(ctx, 4<<20, func(w io.Writer) error {
					_, err := w.Write(bytes.Repeat([]byte("ELF"), 4<<20/3))
					return err
				}, &symbolUploadRequestMetadata{}, []int{0, 1})
			}()
			select {
			case err := <-healthy:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("healthy endpoint was held back by the other endpoint")
			}
			cancel() // Release a stalled endpoint.
			require.Error(t, <-done, "the failed endpoint keeps the upload retryable")
		})
	}
}

// Input read failures are extraction errors; failures writing to the upload are not.
func TestSendSymbolSourceClassifiesErrors(t *testing.T) {
	readErr := errors.New("input read failed")
	for _, tt := range []struct {
		name       string
		status     int
		writeELF   func(io.Writer) error
		wantSource error
		wantErr    bool
	}{
		{"source", http.StatusOK, func(io.Writer) error { return readErr }, readErr, true},
		{"intake", http.StatusInternalServerError, func(w io.Writer) error {
			_, err := w.Write(bytes.Repeat([]byte{1}, 1<<20))
			return err
		}, nil, true},
		{"success", http.StatusOK, func(w io.Writer) error {
			_, err := w.Write([]byte("elf"))
			return err
		}, nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
			require.NoError(t, err)
			uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if tt.status != http.StatusOK {
					// Reject early, without draining, so the producer sees a closed output.
					return httpmock.NewStringResponse(tt.status, ""), nil
				}
				_, err := io.Copy(io.Discard, req.Body)
				return httpmock.NewStringResponse(tt.status, ""), err
			})
			sourceErr, err := uploader.sendSymbolSource(t.Context(), 1<<20, tt.writeELF, &symbolUploadRequestMetadata{}, []int{0})
			require.Equal(t, tt.wantErr, err != nil, "err=%v", err)
			require.Equal(t, tt.wantSource, sourceErr)
		})
	}
}

type failingSymbolWriter struct {
	err error
}

func (w failingSymbolWriter) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return 0, w.err
	}
	return len(p), nil
}

func TestSymbolPayloadCompressionErrors(t *testing.T) {
	failure := errors.New("symbol I/O failed")
	for _, producerFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("producer=%v", producerFailure), func(t *testing.T) {
			var out bytes.Buffer
			var target io.Writer = &out
			if !producerFailure {
				target = failingSymbolWriter{failure}
			}
			mw := multipart.NewWriter(target)
			err := writeSymbolRequestBody(func(w io.Writer) error {
				if _, err := w.Write([]byte("small payload buffered until encoder Close")); err != nil {
					return err
				}
				if producerFailure {
					return failure
				}
				return nil
			}, int64(len("small payload buffered until encoder Close")), &symbolUploadRequestMetadata{}, mw)
			require.ErrorIs(t, err, failure, "both source and frame-finalization errors must fail the upload")
			require.NotContains(t, out.String(), "event.json", "do not publish metadata after failed ELF encoding")
		})
	}
}

func TestStreamingCompressionFailures(t *testing.T) {
	exe := buildGo(t, t.TempDir(), "whole_symbol_failure", buildOptions{symtab: true, debugInfos: true, uncompressedDWARF: true})
	for _, failure := range []string{"destination", "cancellation", "dry run"} {
		t.Run(failure, func(t *testing.T) {
			e, err := symbol.NewElfFromDisk(exe)
			require.NoError(t, err)
			defer e.Close()
			t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
			uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			uploader.dryRun = failure == "dry run"
			calls := make(chan struct{}, 2)
			uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls <- struct{}{}
				if failure == "cancellation" {
					cancel()
					return nil, ctx.Err()
				}
				_, err := io.Copy(io.Discard, req.Body)
				return httpmock.NewStringResponse(http.StatusServiceUnavailable, ""), err
			})
			require.Equal(t, failure == "dry run", uploader.upload(ctx, e, []int{0, 1}))
			if failure == "dry run" {
				require.Empty(t, calls)
			} else {
				require.Len(t, calls, 2)
			}
		})
	}
}

func TestStreamingSymbolUploadRetryAfterFailure(t *testing.T) {
	reports := captureUploadReports(t)
	executable, err := os.Executable()
	require.NoError(t, err)
	uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true, uploadGoPCLnTab: true})
	require.NoError(t, err)
	metadata := newExecutableMetadata(t, executable)
	// Drive admission, retrieval and upload synchronously; no backend query is
	// needed to verify cache eviction and retry eligibility.
	uploader.retrievalQueue = make(chan *reporter.ExecutableMetadata, 1)
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			uploader.UploadSymbols(metadata)
			require.Len(t, uploader.retrievalQueue, 1, "a failed upload must allow the same executable to be queued again")
			retrieved := make(chan *symbol.Elf, 1)
			uploader.symbolRetrievalWorker(t.Context(), <-uploader.retrievalQueue, retrieved)
			require.Len(t, retrieved, 1)
			e := <-retrieved
			_, cached := uploader.uploadCache.Get(e.FileID())
			require.True(t, cached, "retrieval must reserve the cache entry before upload")

			calls := 0
			uploader.client.Transport = symbolUploadRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if status == http.StatusOK {
					if _, err := io.Copy(io.Discard, req.Body); err != nil {
						return nil, err
					}
				}
				return httpmock.NewStringResponse(status, ""), nil
			})
			uploader.uploadWorker(t.Context(), ElfWithBackendSources{
				Elf: e, BackendSymbolSources: []SymbolQueryResult{{SymbolSource: symbol.SourceNone}},
			})
			require.Equal(t, 1, calls, "the attempt must reach the streaming transport")
			_, cached = uploader.uploadCache.Get(e.FileID())
			require.Equal(t, status == http.StatusOK, cached, "failure must evict the entry; success must retain it")
		})
	}
	uploader.UploadSymbols(metadata)
	require.Empty(t, uploader.retrievalQueue, "a successful retry must suppress further uploads")
	uploader.reporter.flush()
	require.Equal(t, map[string]int{reasonIntakeError: 1, reasonUploaded: 1, reasonAlreadyUploaded: 1}, uploadReportCounts(t, reports))
}

func TestStreamingReportsUnsupportedELF(t *testing.T) {
	reports := captureUploadReports(t)
	uploader, err := newTestUploader(t.Context(), uploaderOpts{streamSymbols: true})
	require.NoError(t, err)
	e := symbol.NewElfForTest("/unsupported", runtime.GOARCH, "build-id", "", libpf.FileID{})
	uploader.reportExtractError(e, fmt.Errorf("plan symbol ELF: %w", elfstream.ErrUnsupported))
	uploader.reportExtractError(e, errors.New("malformed"))
	uploader.reporter.flush()
	require.Equal(t, map[string]int{reasonUnsupportedELF: 1, reasonExtractError: 1}, uploadReportCounts(t, reports))
}

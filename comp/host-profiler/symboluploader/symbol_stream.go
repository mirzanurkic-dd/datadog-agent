// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package symboluploader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbol"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbolcopier"
	"github.com/DataDog/datadog-agent/pkg/util/elfstream"
	"github.com/DataDog/datadog-agent/pkg/zstd"
)

// uploadSymbolStream plans e's symbol ELF and streams it to the endpoints,
// without objcopy or temporary files. Like the objcopy path, extraction (here
// planning) gets symbolCopyTimeout and the upload, which includes encoding,
// gets uploadTimeout. It reports and logs like the objcopy path, and returns
// true on success.
func (d *DatadogSymbolUploader) uploadSymbolStream(ctx context.Context, e *symbol.Elf, endpointIndices []int) bool {
	planCtx, cancelPlan := context.WithTimeout(ctx, symbolCopyTimeout)
	stream, metadata, err := d.planSymbolStream(planCtx, e)
	cancelPlan()
	if err != nil {
		d.reportExtractError(e, err)
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	if d.dryRun {
		if err := stream.Write(ctx, io.Discard); err != nil {
			d.reportExtractError(e, err)
			return false
		}
		slog.Info("Dry run: would upload symbols for executable", slog.String("executable", e.String()))
		return true
	}
	sourceErr, err := d.sendSymbolSource(ctx, stream.Size(), func(w io.Writer) error { return stream.Write(ctx, w) }, metadata, endpointIndices)
	switch {
	case sourceErr != nil:
		d.reportExtractError(e, sourceErr)
		return false
	case err != nil:
		d.reportIntakeError(e, err)
		return false
	}
	d.reporter.Info(reasonUploaded, 1, e.Path())
	return true
}

// planSymbolStream selects the symbol source and plans its exported ELF.
func (d *DatadogSymbolUploader) planSymbolStream(ctx context.Context, e *symbol.Elf) (*elfstream.ELFStream, *symbolUploadRequestMetadata, error) {
	// Read the already-open file (or in-memory VDSO): reopening the path could
	// pick up a replaced file.
	input, size, err := e.SymbolReader()
	if err != nil {
		return nil, nil, err
	}
	source, goInfo, _ := d.getSymbolSourceWithGoPCLnTab(e)
	var keep []symbol.SectionInfo
	// Debug sections and static symbols are always kept; dynamic symbols need
	// their sections named, as in the objcopy path.
	if source == symbol.SourceDynamicSymbolTable {
		keep = e.GetSectionsRequiredForDynamicSymbols()
	}
	stream, err := symbolcopier.NewSymbolStream(ctx, input, size, goInfo, keep)
	if err != nil {
		return nil, nil, fmt.Errorf("plan symbol ELF: %w", err)
	}
	return stream, newSymbolUploadRequestMetadata(e, source, d.name, d.version), nil
}

// sendSymbolSource is sendSymbolStream that also returns sourceErr: writeELF's
// error when it came from reading the input rather than from the upload or the
// deadline.
func (d *DatadogSymbolUploader) sendSymbolSource(ctx context.Context, size int64, writeELF func(io.Writer) error, metadata *symbolUploadRequestMetadata, indices []int) (sourceErr, err error) {
	var mu sync.Mutex
	err = d.sendSymbolStream(ctx, size, func(w io.Writer) error {
		out := &outputErrorWriter{w: w}
		writeErr := writeELF(out)
		if writeErr != nil && out.err == nil && ctx.Err() == nil {
			mu.Lock()
			if sourceErr == nil {
				sourceErr = writeErr
			}
			mu.Unlock()
		}
		return writeErr
	}, metadata, indices)
	return sourceErr, err
}

// outputErrorWriter records the output's write error.
type outputErrorWriter struct {
	w   io.Writer
	err error
}

func (o *outputErrorWriter) Write(p []byte) (int, error) {
	n, err := o.w.Write(p)
	if err != nil {
		o.err = err
	}
	return n, err
}

// sendSymbolStream sends the symbol ELF to every endpoint in indices. Each
// endpoint gets its own write of the ELF, encoder and request, like the objcopy
// path's per-endpoint uploads, so a slow or failing endpoint does not hold back
// the others. writeELF must therefore be safe to call concurrently.
func (d *DatadogSymbolUploader) sendSymbolStream(ctx context.Context, size int64, writeELF func(io.Writer) error, metadata *symbolUploadRequestMetadata, indices []int) error {
	var uploads errgroup.Group
	for _, index := range indices {
		uploads.Go(func() error {
			return sendMultipartStream(ctx, d.client,
				func(body io.Reader, contentType string) (*http.Request, error) {
					return d.buildSymbolUploadRequest(ctx, body, contentType, "", index)
				},
				func(mw *multipart.Writer) error { return writeSymbolRequestBody(writeELF, size, metadata, mw) })
		})
	}
	return uploads.Wait()
}

// reportExtractError and reportIntakeError report and log like the objcopy path.
// Layouts the stream writer does not handle get their own report reason.
func (d *DatadogSymbolUploader) reportExtractError(e *symbol.Elf, err error) {
	reason := reasonExtractError
	if errors.Is(err, elfstream.ErrUnsupported) {
		reason = reasonUnsupportedELF
	}
	d.reporter.Error(reason, 1, e.Path())
	slog.Error("Failed to create symbol file",
		slog.String("executable", e.String()),
		slog.String("error", err.Error()))
}

func (d *DatadogSymbolUploader) reportIntakeError(e *symbol.Elf, err error) {
	d.reporter.Error(reasonIntakeError, 1, e.Path())
	slog.Error("Failed to upload symbols",
		slog.String("error", err.Error()),
		slog.String("executable", e.String()))
}

// symbolCompressionLevel trades a little payload size for less CPU. Measured on
// arm64 with 14 real inputs, the pure-Go encoder's fastest level used ~27% less
// CPU than its default for ~2.5% larger payloads; the encoder is ~90% of
// streaming upload CPU.
const symbolCompressionLevel = zstd.BestSpeed

// symbolCompressionWindowLog returns the log2 of the smallest window covering the
// ELF, from 128 KiB, which keeps the default block size, to the default 8 MiB.
func symbolCompressionWindowLog(size int64) int {
	log := 17
	for int64(1)<<log < size && log < 23 {
		log++
	}
	return log
}

// writeSymbolRequestBody writes the zstd-compressed ELF part, then the JSON event part.
// The caller closes mw after these parts to write the final multipart boundary.
func writeSymbolRequestBody(writeELF func(io.Writer) error, size int64, e *symbolUploadRequestMetadata, mw *multipart.Writer) error {
	filePart, err := mw.CreateFormFile("elf_symbol_file", "elf_symbol_file")
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	// Symbol Platform detects the zstd frame magic in the stored ELF blob.
	// Compress only the file part: multipart framing and JSON stay unencoded.
	// The host profiler builds pure Go, so these options apply; the CGO backend
	// ignores them.
	compressed, err := zstd.NewWriterLevelWithOptions(filePart, symbolCompressionLevel,
		zstd.WithWindowLogSize(symbolCompressionWindowLog(size)),
		zstd.WithDisableLowerEncoderMem(),
	)
	if err != nil {
		return fmt.Errorf("failed to create symbol encoder: %w", err)
	}
	writeErr := writeELF(compressed)
	closeErr := compressed.Close() // Finish the frame before opening the JSON part.
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("failed to compress symbol file: %w", err)
	}

	// Write the event metadata into the multipart writer
	eventPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="event"; filename="event.json"`},
		"Content-Type":        []string{"application/json"},
	})
	if err != nil {
		return fmt.Errorf("failed to create event part: %w", err)
	}

	err = json.NewEncoder(eventPart).Encode(e)
	if err != nil {
		return fmt.Errorf("failed to write JSON metadata: %w", err)
	}

	return nil
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

// Command symbolcheck exports ELF files like the host profiler's symbol uploader
// and validates each exported ELF against its input. It is a manual QA tool:
//
//	symbolcheck [-objcopy] [-keep DIR] PATH...
//
// PATH may be an ELF file or a directory, which is walked for ELF files. Streaming
// export is always checked; -objcopy also checks the objcopy export, which, like
// the profiler, runs objcopy with CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH ambient
// capabilities (run as root, or grant them). Non-ELF files and inputs without
// symbols are skipped. The exit status is 1 if any check fails.
package main

import (
	"context"
	"debug/elf" //nolint:depguard // ELF header constants are not exposed by safeelf.
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/pclntab"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbol"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbolcopier"
)

var errSkipped = errors.New("skipped")

func main() {
	objcopy := flag.Bool("objcopy", false, "also export and validate with objcopy")
	keep := flag.String("keep", "", "write exported ELFs to this directory instead of deleting them")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: symbolcheck [-objcopy] [-keep DIR] PATH...")
		os.Exit(2)
	}
	exporters := []string{"stream"}
	if *objcopy {
		exporters = append(exporters, "objcopy")
	}
	failed := false
	for _, root := range flag.Args() {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !entry.Type().IsRegular() {
				return err
			}
			for _, exporter := range exporters {
				err := check(path, exporter, *keep)
				switch {
				case errors.Is(err, errSkipped):
				case err != nil:
					failed = true
					fmt.Printf("FAIL %s %s: %v\n", exporter, path, err)
				default:
					fmt.Printf("PASS %s %s\n", exporter, path)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// isLoadableELF reports whether path is an ELF executable or shared object,
// the only types the profiler loads; relocatable objects, archives and dwz
// supplementary files are not. Read errors are reported, not skipped.
func isLoadableELF(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var header [18]byte // e_ident, then e_type.
	if _, err := io.ReadFull(f, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	if string(header[:4]) != elf.ELFMAG {
		return false, nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	if elf.Data(header[elf.EI_DATA]) == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}
	typ := elf.Type(order.Uint16(header[16:]))
	return typ == elf.ET_EXEC || typ == elf.ET_DYN, nil
}

// check exports the file the uploader would read for path with exporter, and
// validates the result against that file. Only files the profiler would not
// load are skipped.
func check(path, exporter, keep string) error {
	if ok, err := isLoadableELF(path); err != nil || !ok {
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		return errSkipped
	}
	e, err := symbol.NewElfFromDisk(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer e.Close()
	// Like the uploader, read the file that provides the best symbols: path
	// itself, or a separate debug file it points to.
	input := e.SymbolPathOnDisk()
	source := e.SymbolSource()
	var goInfo *pclntab.GoPCLnTabInfo
	if e.IsGolang() {
		// Like the uploader, fall back to other symbols when Go tables are
		// unusable, such as an omitted .gopclntab in a separate debug file.
		if info, err := e.GoPCLnTab(); err == nil {
			goInfo = info
		}
	}
	if goInfo == nil && source == symbol.SourceNone {
		return errSkipped
	}
	// Select sections like the uploader, with dynamic symbols enabled.
	var keepSections []symbol.SectionInfo
	if source == symbol.SourceDynamicSymbolTable {
		keepSections = e.GetSectionsRequiredForDynamicSymbols()
	}

	dir := keep
	if dir == "" {
		if dir, err = os.MkdirTemp("", "symbolcheck"); err != nil {
			return err
		}
		defer os.RemoveAll(dir)
	}
	output := filepath.Join(dir, filepath.Base(path)+"."+exporter)
	if err := export(input, output, exporter, goInfo, keepSections); err != nil {
		return fmt.Errorf("export %s: %w", input, err)
	}
	_, err = validateArtifactPath(input, output, goInfo != nil)
	return err
}

// export reads path and writes its exported ELF to output.
func export(path, output, exporter string, goInfo *pclntab.GoPCLnTabInfo, keep []symbol.SectionInfo) error {
	ctx := context.Background()
	if exporter == "objcopy" {
		// Match the uploader: compress debug sections when objcopy supports zstd.
		return symbolcopier.CopySymbols(ctx, path, output, goInfo, keep, symboluploader.CheckObjcopyZstdSupport(ctx))
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	stat, err := input.Stat()
	if err != nil {
		return err
	}
	stream, err := symbolcopier.NewSymbolStream(ctx, input, stat.Size(), goInfo, keep)
	if err != nil {
		return err
	}
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	return errors.Join(stream.Write(ctx, out), out.Close())
}

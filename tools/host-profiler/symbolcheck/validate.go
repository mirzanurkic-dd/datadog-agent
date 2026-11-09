// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf" //nolint:depguard // Independent validation, not the production ELF planner.
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/pclntab"
	"github.com/DataDog/datadog-agent/comp/host-profiler/symboluploader/symbol"
)

type artifactCoverage struct {
	PayloadSections       int `json:"payload_sections"`
	DWARFSections         int `json:"dwarf_sections"`
	StaticSymbols         int `json:"static_symbols"`
	DynamicSymbols        int `json:"dynamic_symbols"`
	LoadRanges            int `json:"load_ranges"`
	GoDataSections        int `json:"go_data_sections"`
	IgnoredSectionSymbols int `json:"ignored_section_symbols"`
}

type sectionContent struct {
	Type    elf.SectionType
	Flags   elf.SectionFlag
	Address uint64
	Bytes   int64
	Hash    [sha256.Size]byte
}

type namedSymbol struct {
	Symbol  elf.Symbol
	Section string
}

func canonicalSectionName(name string) string {
	if suffix, ok := strings.CutPrefix(name, ".zdebug_"); ok {
		return ".debug_" + suffix
	}
	return name
}

func artifactContents(f *elf.File) (map[string]sectionContent, error) {
	out := make(map[string]sectionContent)
	for _, s := range f.Sections {
		// Compiler provenance is not symbolization input. Objcopy retains
		// .comment; the streaming debug-only selection intentionally does not.
		if s.Name == ".comment" {
			continue
		}
		switch s.Type {
		case elf.SHT_NULL, elf.SHT_NOBITS, elf.SHT_SYMTAB, elf.SHT_DYNSYM:
			continue
		case elf.SHT_STRTAB:
			if !strings.HasPrefix(s.Name, ".debug_") && !strings.HasPrefix(s.Name, ".zdebug_") {
				continue
			}
		}
		// Names may repeat (for example, unnamed notes): key repeats by order.
		name := canonicalSectionName(s.Name)
		for i := 2; ; i++ {
			if _, exists := out[name]; !exists {
				break
			}
			name = fmt.Sprintf("%s#%d", canonicalSectionName(s.Name), i)
		}
		hash := sha256.New()
		// debug/elf handles both SHF_COMPRESSED and legacy GNU zlib.
		// Opening a legacy section also resolves its logical Size.
		n, err := io.Copy(hash, s.Open())
		if err != nil {
			return nil, fmt.Errorf("reading section %q: %w", s.Name, err)
		}
		if uint64(n) != s.Size {
			return nil, fmt.Errorf("section %q logical size differs: read=%d declared=%d", s.Name, n, s.Size)
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		// Compression encoding may differ in objcopy. The streamer must
		// separately preserve source compression bytes (existing unit test).
		out[name] = sectionContent{s.Type, s.Flags &^ elf.SHF_COMPRESSED, s.Addr, n, digest}
	}
	return out, nil
}

func hashArtifactBytes(data []byte) [sha256.Size]byte {
	return sha256.Sum256(data)
}

func hasStaticSymbolReferences(output *elf.File) bool {
	for _, s := range output.Sections {
		if s.Type == elf.SHT_NULL || s.Type == elf.SHT_NOBITS || s.Size == 0 {
			continue
		}
		// Group signatures are symbol references too. Keep groups strict even
		// when their link is malformed rather than treating them as unreferenced.
		if s.Type == elf.SHT_GROUP || uint64(s.Link) >= uint64(len(output.Sections)) || output.Sections[s.Link].Type == elf.SHT_SYMTAB {
			return true
		}
		if (s.Type == elf.SHT_REL || s.Type == shtRela) && output.Sections[s.Link].Type != elf.SHT_DYNSYM {
			return true
		}
	}
	return false
}

// shtRela is the relocations-with-addends section type; misspell flags its elf name.
const shtRela = elf.SHT_RELA //nolint:misspell

// validateArtifactPath checks an exported ELF against its input, never against
// another exporter's output: identity, payloads, references, symbols, Go tables
// and consumer-readable DWARF.
// isGo checks Go tables; pass it only when the input's tables are usable.
func validateArtifactPath(input, output string, isGo bool) (artifactCoverage, error) {
	original, err := elf.Open(input)
	if err != nil {
		return artifactCoverage{}, err
	}
	defer original.Close()
	artifact, err := elf.Open(output)
	if err != nil {
		return artifactCoverage{}, err
	}
	defer artifact.Close()
	selection, err := symbol.NewElfFromDisk(input)
	if err != nil {
		return artifactCoverage{}, err
	}
	keepDynamic := selection.SymbolSource() == symbol.SourceDynamicSymbolTable
	selection.Close()
	var info *pclntab.GoPCLnTabInfo
	if isGo {
		var owner *pfelf.File
		info, owner, err = readArtifactGoData(input)
		if err != nil {
			return artifactCoverage{}, fmt.Errorf("input Go consumer: %w", err)
		}
		defer owner.Close()
	}
	coverage, validationErr := validateArtifact(original, artifact, info, keepDynamic)
	if validationErr != nil {
		// A failed structural/content check already rejects this artifact. Do
		// not repeatedly walk entire DWARF programs for each corrupt payload.
		return coverage, validationErr
	}
	if info != nil {
		actual, owner, err := readArtifactGoData(output)
		if err != nil {
			validationErr = errors.Join(validationErr, fmt.Errorf("output Go consumer: %w", err))
		} else {
			defer owner.Close()
			var differ []string
			for name, same := range map[string]bool{
				"address":      actual.Address == info.Address,
				"text start":   actual.TextStart.Address == info.TextStart.Address,
				"version":      actual.Version == info.Version,
				"gofunc addr":  actual.GoFuncAddr == info.GoFuncAddr,
				"pclntab data": bytes.Equal(actual.Data, info.Data),
				// Without the input's runtime.gcbits.* bound, the parser trims the
				// exported gofunc to the inline trees it uses: a prefix is equivalent.
				"gofunc data": bytes.HasPrefix(info.GoFuncData, actual.GoFuncData) &&
					(len(actual.GoFuncData) != 0 || len(info.GoFuncData) == 0),
			} {
				if !same {
					differ = append(differ, name)
				}
			}
			if len(differ) != 0 {
				sort.Strings(differ)
				validationErr = errors.Join(validationErr, fmt.Errorf("Go consumer tables/addresses differ from input: %s (gofunc %d vs %d bytes, text start %#x vs %#x)",
					strings.Join(differ, ", "), len(actual.GoFuncData), len(info.GoFuncData), actual.TextStart.Address, info.TextStart.Address))
			}
		}
	}
	section := original.Section(".debug_info")
	if section == nil {
		section = original.Section(".zdebug_info")
	}
	if section != nil && section.Type != elf.SHT_NOBITS {
		// Payload equality above ties all DWARF bytes to the source. Additionally
		// require the output's records/line programs to be usable by a consumer,
		// when the input's are; some inputs are unreadable by debug/elf already.
		if readArtifactDWARF(original) == nil {
			validationErr = errors.Join(validationErr, readArtifactDWARF(artifact))
		}
	}
	return coverage, validationErr
}

// The returned tables may borrow the file's mmap. Keep their owner open until
// all hashing, parsing and comparisons are finished; do not copy whole tables.
func readArtifactGoData(path string) (*pclntab.GoPCLnTabInfo, *pfelf.File, error) {
	file, err := pfelf.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := pclntab.FindGoPCLnTabWithChecks(file)
	if err == nil && info == nil {
		err = errors.New("missing Go tables")
	}
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return info, file, nil
}

func readArtifactDWARF(file *elf.File) error {
	data, err := file.DWARF()
	if err != nil {
		return fmt.Errorf("DWARF consumer: %w", err)
	}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("DWARF records: %w", err)
		}
		if entry == nil {
			return nil
		}
		if entry.Tag != dwarf.TagCompileUnit || entry.Val(dwarf.AttrStmtList) == nil {
			continue
		}
		lines, err := data.LineReader(entry)
		if err != nil {
			return fmt.Errorf("DWARF line reader: %w", err)
		}
		if lines == nil {
			return errors.New("missing DWARF line program")
		}
		var line dwarf.LineEntry
		for {
			if err := lines.Next(&line); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("DWARF lines: %w", err)
			}
		}
	}
}

func goSectionName(name string) string {
	if name == ".data.rel.ro.gopclntab" {
		return ".gopclntab"
	}
	return canonicalSectionName(name)
}

func validateArtifact(original, output *elf.File, info *pclntab.GoPCLnTabInfo, keepDynamic bool) (coverage artifactCoverage, err error) {
	var failures []error
	failures = append(failures, validateArtifactReferences(original, output))
	if original.FileHeader != output.FileHeader {
		failures = append(failures, errors.New("ELF identity differs from input"))
	}
	before, err := artifactContents(original)
	if err != nil {
		return coverage, fmt.Errorf("input payloads: %w", err)
	}
	after, err := artifactContents(output)
	if err != nil {
		return coverage, fmt.Errorf("output payloads: %w", err)
	}
	// Resolve index-bearing payloads through their own tables before comparing.
	// Correct symbol/section renumbering is not a payload corruption.
	for _, item := range []struct {
		file     *elf.File
		contents map[string]sectionContent
	}{{original, before}, {output, after}} {
		if err := resolveArtifactReferenceContents(item.file, item.contents); err != nil {
			return coverage, err
		}
	}
	if info != nil {
		before[".gopclntab"] = goSectionContent(info.Address, info.Data)
		if len(info.GoFuncData) != 0 {
			before[".gofunc"] = goSectionContent(info.GoFuncAddr, info.GoFuncData)
		}
	}
	for name, content := range before {
		// GDB's auto-load script is not DWARF/function data. It may
		// be absent, but is still checked against the source when retained.
		section := original.Section(name)
		requiredRelocation := false
		if section != nil && (section.Type == elf.SHT_REL || section.Type == shtRela) && uint64(section.Info) < uint64(len(original.Sections)) {
			target := original.Sections[section.Info]
			requiredRelocation = strings.HasPrefix(canonicalSectionName(target.Name), ".debug_") && target.Name != ".debug_gdb_scripts" || target.Type == elf.SHT_NOTE
		}
		required := requiredRelocation || strings.HasPrefix(name, ".debug_") && name != ".debug_gdb_scripts" ||
			section != nil && section.Type == elf.SHT_NOTE ||
			info != nil && (name == ".gopclntab" || name == ".gofunc" && len(info.GoFuncData) != 0)
		actual, present := after[name]
		if !present {
			if required {
				failures = append(failures, fmt.Errorf("missing source payload %q", name))
			}
			continue
		}
		if info != nil && (name == ".gopclntab" || name == ".gofunc") {
			// Extracted Go tables may have lived inside a different input section.
			// Allocation flags are not needed on an extracted metadata section.
			actual.Flags &^= elf.SHF_ALLOC
		}
		if actual != content {
			failures = append(failures, fmt.Errorf("payload %q differs from input", name))
		}
	}
	for name := range after {
		if _, exists := before[name]; !exists {
			failures = append(failures, fmt.Errorf("unproven output payload %q", name))
		}
		coverage.PayloadSections++
		if strings.HasPrefix(name, ".debug_") {
			coverage.DWARFSections++
		}
		if name == ".gopclntab" || name == ".gofunc" {
			coverage.GoDataSections++
		}
	}
	for _, section := range original.Sections {
		if section.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		actual := output.Section(section.Name)
		if actual == nil || actual.Addr != section.Addr || actual.Size != section.Size || actual.Flags != section.Flags {
			failures = append(failures, fmt.Errorf("code range %q differs from input", section.Name))
		} else if artifactLoadCovers(original, section) && !artifactLoadCovers(output, actual) {
			failures = append(failures, fmt.Errorf("code range %q is not covered by an executable LOAD", section.Name))
		}
	}
	starts := make(map[[2]uint64]bool)
	sourceBase, outputBase := ^uint64(0), ^uint64(0)
	for _, program := range original.Progs {
		if program.Type == elf.PT_LOAD {
			starts[[2]uint64{program.Vaddr, uint64(program.Flags)}] = true
			sourceBase = min(sourceBase, program.Vaddr)
		}
	}
	for _, program := range output.Progs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		coverage.LoadRanges++
		outputBase = min(outputBase, program.Vaddr)
		if !starts[[2]uint64{program.Vaddr, uint64(program.Flags)}] || program.Memsz > ^uint64(0)-program.Vaddr {
			failures = append(failures, errors.New("LOAD start/permissions differ from input or range overflows"))
		}
	}
	if sourceBase != outputBase {
		failures = append(failures, errors.New("LOAD image base differs from input"))
	}
	for _, dynamic := range []bool{false, true} {
		count, anchors, err := validateArtifactSymbols(original, output, info, dynamic, !dynamic || keepDynamic)
		failures = append(failures, err)
		coverage.IgnoredSectionSymbols += anchors
		if dynamic {
			coverage.DynamicSymbols = count
		} else {
			coverage.StaticSymbols = count
		}
	}
	return coverage, errors.Join(failures...)
}

// The only payloads containing ELF table indices retained by the selection
// policy are relocations and groups. Canonicalize those references, not bytes.
func resolveArtifactReferenceContents(file *elf.File, contents map[string]sectionContent) error {
	for _, section := range file.Sections {
		if section.Type != elf.SHT_REL && section.Type != shtRela && section.Type != elf.SHT_GROUP {
			continue
		}
		if section.Link == 0 && section.Type != elf.SHT_GROUP {
			continue // Relocations without a symbol table, such as IRELATIVE-only .rela.plt.
		}
		if uint64(section.Link) >= uint64(len(file.Sections)) {
			return errors.New("reference table link is outside section table")
		}
		table := file.Sections[section.Link]
		if table.Type != elf.SHT_SYMTAB && table.Type != elf.SHT_DYNSYM {
			return fmt.Errorf("reference table %q links to %q (%v), not symbols", section.Name, table.Name, table.Type)
		}
		syms, err := artifactSymbolTable(file, table.Type == elf.SHT_DYNSYM)
		if err != nil {
			return err
		}
		resolve := func(index uint64) (namedSymbol, error) {
			if index == 0 {
				return namedSymbol{}, nil
			}
			if index > uint64(len(syms)) {
				return namedSymbol{}, errors.New("reference has an invalid symbol index")
			}
			sym := syms[index-1]
			sym.HasVersion, sym.VersionIndex, sym.Version, sym.Library = false, 0, "", ""
			return artifactSymbolKey(file, sym)
		}
		data, err := section.Data()
		if err != nil {
			return err
		}
		type reference struct {
			Offset, Type, Addend uint64
			Symbol               namedSymbol
		}
		var records []reference
		var members []string
		if section.Type == elf.SHT_GROUP {
			if len(data) < 4 || len(data)%4 != 0 || section.Info == 0 {
				return errors.New("invalid group payload/signature")
			}
			signature, err := resolve(uint64(section.Info))
			if err != nil {
				return err
			}
			records = append(records, reference{Type: uint64(file.ByteOrder.Uint32(data)), Symbol: signature})
			for offset := 4; offset < len(data); offset += 4 {
				index := file.ByteOrder.Uint32(data[offset:])
				if index == 0 || uint64(index) >= uint64(len(file.Sections)) {
					return errors.New("invalid group member")
				}
				members = append(members, goSectionName(file.Sections[index].Name))
			}
			sort.Strings(members)
		} else {
			stride := binary.Size(elf.Rel64{})
			if section.Type == shtRela {
				stride = binary.Size(elf.Rela64{})
			}
			if len(data)%stride != 0 || section.Entsize != uint64(stride) {
				return errors.New("invalid relocation stride")
			}
			for offset := 0; offset < len(data); offset += stride {
				info := file.ByteOrder.Uint64(data[offset+8:])
				sym, err := resolve(info >> 32)
				if err != nil {
					return err
				}
				record := reference{Offset: file.ByteOrder.Uint64(data[offset:]), Type: uint64(uint32(info)), Symbol: sym}
				if section.Type == shtRela {
					record.Addend = file.ByteOrder.Uint64(data[offset+16:])
				}
				records = append(records, record)
			}
		}
		canonical, err := json.Marshal(struct {
			Records []reference
			Members []string
		}{records, members})
		if err != nil {
			return err
		}
		key := canonicalSectionName(section.Name)
		content := contents[key]
		content.Hash = hashArtifactBytes(canonical)
		contents[key] = content
	}
	return nil
}

func artifactLoadCovers(file *elf.File, section *elf.Section) bool {
	for _, program := range file.Progs {
		if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 && section.Addr >= program.Vaddr &&
			section.Addr-program.Vaddr <= program.Memsz && section.Size <= program.Memsz-(section.Addr-program.Vaddr) {
			return true
		}
	}
	return false
}

func validateArtifactReferences(original, output *elf.File) error {
	if output.Class != elf.ELFCLASS64 {
		return errors.New("semantic gate supports ELF64 only")
	}
	names := make(map[string]bool)
	for _, section := range output.Sections {
		if section.Type == elf.SHT_NULL {
			continue
		}
		if section.Name != "" && names[section.Name] {
			return fmt.Errorf("ambiguous section name %q", section.Name)
		}
		names[section.Name] = true
		if section.Type == elf.SHT_NOBITS {
			continue
		}
		if uint64(section.Link) >= uint64(len(output.Sections)) {
			return fmt.Errorf("section %q link is outside section table", section.Name)
		}
		if source := original.Section(section.Name); source != nil && source.Link != 0 {
			if uint64(source.Link) >= uint64(len(original.Sections)) ||
				goSectionName(original.Sections[source.Link].Name) != goSectionName(output.Sections[section.Link].Name) {
				return fmt.Errorf("section %q link resolves to the wrong owner", section.Name)
			}
		}
		if section.Type != elf.SHT_REL && section.Type != shtRela && section.Type != elf.SHT_GROUP {
			continue
		}
		table := output.Sections[section.Link]
		if table.Type != elf.SHT_SYMTAB && table.Type != elf.SHT_DYNSYM || table.Entsize != elf.Sym64Size {
			return fmt.Errorf("section %q does not link to a symbol table", section.Name)
		}
		if section.Type == elf.SHT_GROUP {
			if section.Info == 0 || uint64(section.Info) >= table.Size/elf.Sym64Size || section.Size < 4 || section.Size%4 != 0 || section.Entsize != 4 {
				return fmt.Errorf("invalid group %q", section.Name)
			}
			continue
		}
		stride := uint64(binary.Size(elf.Rel64{}))
		if section.Type == shtRela {
			stride = uint64(binary.Size(elf.Rela64{}))
		}
		if section.Entsize != stride || section.Size%stride != 0 || uint64(section.Info) >= uint64(len(output.Sections)) {
			return fmt.Errorf("invalid relocation table %q", section.Name)
		}
		if source := original.Section(section.Name); source != nil && source.Info != 0 {
			if uint64(source.Info) >= uint64(len(original.Sections)) ||
				goSectionName(original.Sections[source.Info].Name) != goSectionName(output.Sections[section.Info].Name) {
				return fmt.Errorf("relocations %q have the wrong target", section.Name)
			}
		}
	}
	return nil
}

func goSectionContent(address uint64, data []byte) sectionContent {
	return sectionContent{Type: elf.SHT_PROGBITS, Address: address, Bytes: int64(len(data)), Hash: hashArtifactBytes(data)}
}

func artifactSymbolKey(file *elf.File, sym elf.Symbol) (namedSymbol, error) {
	section := sym.Section.String()
	if sym.Section > elf.SHN_UNDEF && sym.Section < elf.SHN_LORESERVE {
		if int(sym.Section) >= len(file.Sections) || file.Sections[sym.Section].Type == elf.SHT_NULL {
			return namedSymbol{}, fmt.Errorf("symbol %q has invalid section", sym.Name)
		}
		section = goSectionName(file.Sections[sym.Section].Name)
		sym.Section = 0
	} else if sym.Section == elf.SHN_XINDEX {
		return namedSymbol{}, errors.New("extended symbol indices are unsupported")
	}
	return namedSymbol{sym, section}, nil
}

func artifactSymbolTable(file *elf.File, dynamic bool) ([]elf.Symbol, error) {
	typ := elf.SHT_SYMTAB
	if dynamic {
		typ = elf.SHT_DYNSYM
	}
	tables := 0
	for _, section := range file.Sections {
		if section.Type == typ {
			tables++
		}
	}
	if tables > 1 {
		return nil, errors.New("multiple symbol tables of the same type are unsupported")
	}
	if table := file.SectionByType(typ); table != nil {
		if table.Entsize != elf.Sym64Size || table.Size < elf.Sym64Size || table.Size%elf.Sym64Size != 0 ||
			table.Info == 0 || uint64(table.Info) > table.Size/elf.Sym64Size ||
			uint64(table.Link) >= uint64(len(file.Sections)) || file.Sections[table.Link].Type != elf.SHT_STRTAB {
			return nil, errors.New("invalid symbol table stride/link/local boundary")
		}
		var null [elf.Sym64Size]byte
		if _, err := io.ReadFull(table.Open(), null[:]); err != nil {
			return nil, err
		}
		if null != [elf.Sym64Size]byte{} {
			return nil, errors.New("symbol zero must be undefined and empty")
		}
	}
	var syms []elf.Symbol
	var err error
	if dynamic {
		syms, err = file.DynamicSymbols()
	} else {
		syms, err = file.Symbols()
	}
	if errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil
	}
	if err == nil {
		table := file.SectionByType(typ)
		for i, sym := range syms {
			if (uint64(i+1) < uint64(table.Info)) != (elf.ST_BIND(sym.Info) == elf.STB_LOCAL) {
				return nil, errors.New("symbol ordering disagrees with local/global boundary")
			}
		}
	}
	return syms, err
}

// Only Go marker representations consumed by name/address are interchangeable.
// pfelf.VisitSymbols and pclntab's marker lookup do not filter binding/type;
// validateArtifactPath additionally requires the consumer to recover identical
// complete Go tables. No ordinary symbol's attributes are normalized.
func artifactGoMarker(sym elf.Symbol, info *pclntab.GoPCLnTabInfo) (address uint64, section string, ok bool) {
	if info == nil {
		return 0, "", false
	}
	switch sym.Name {
	case "runtime.text":
		return info.TextStart.Address, ".text", info.TextStart.Address != 0
	case "go:func.*":
		section = ".gopclntab"
		if len(info.GoFuncData) != 0 {
			section = ".gofunc"
		}
		return info.GoFuncAddr, section, info.GoFuncAddr != 0
	}
	return 0, "", false
}

func canonicalSectionAnchor(key namedSymbol, file *elf.File) bool {
	if key.Symbol.Name != "" || key.Symbol.Info != byte(elf.STT_SECTION) || key.Symbol.Other != 0 || key.Symbol.Size != 0 {
		return false
	}
	for _, section := range file.Sections {
		if goSectionName(section.Name) == key.Section && section.Type != elf.SHT_NULL && key.Symbol.Value == section.Addr {
			return true
		}
	}
	return false
}

func optionalGoAlias(key namedSymbol, info *pclntab.GoPCLnTabInfo) bool {
	if info == nil || key.Section != ".gopclntab" || elf.ST_BIND(key.Symbol.Info) != elf.STB_LOCAL ||
		(elf.ST_TYPE(key.Symbol.Info) != elf.STT_OBJECT && elf.ST_TYPE(key.Symbol.Info) != elf.STT_NOTYPE) {
		return false
	}
	// Local aliases inside the independently recovered pclntab are redundant
	// when the full table is preserved and reparsed. Never omit functions.
	return key.Symbol.Value >= info.Address && key.Symbol.Value-info.Address <= uint64(len(info.Data)) &&
		key.Symbol.Size <= uint64(len(info.Data))-(key.Symbol.Value-info.Address)
}

func validateArtifactSymbols(original, output *elf.File, info *pclntab.GoPCLnTabInfo, dynamic, required bool) (int, int, error) {
	before, err := artifactSymbolTable(original, dynamic)
	if err != nil {
		return 0, 0, err
	}
	after, err := artifactSymbolTable(output, dynamic)
	if err != nil {
		return 0, 0, err
	}
	expected := make(map[namedSymbol]int)
	markers := make(map[string]elf.Symbol)
	for _, sym := range before {
		key, err := artifactSymbolKey(original, sym)
		if err != nil {
			return 0, 0, err
		}
		if dynamic {
			key.Symbol.Version, key.Symbol.Library = "", ""
			key.Symbol.HasVersion, key.Symbol.VersionIndex = false, 0
		}
		if _, _, marker := artifactGoMarker(sym, info); marker && !dynamic {
			if _, duplicate := markers[sym.Name]; duplicate {
				return 0, 0, fmt.Errorf("ambiguous source Go marker %q", sym.Name)
			}
			markers[sym.Name] = sym
			continue
		}
		expected[key]++
	}
	// A regenerated marker is required even if the stripped input had no SYMTAB.
	if info != nil && !dynamic {
		if info.GoFuncAddr != 0 {
			if _, exists := markers["go:func.*"]; !exists {
				markers["go:func.*"] = elf.Symbol{Name: "go:func.*"}
			}
		}
		if info.TextStart.Origin == pclntab.TextStartOriginModuleData && info.TextStart.Address != 0 {
			if _, exists := markers["runtime.text"]; !exists {
				markers["runtime.text"] = elf.Symbol{Name: "runtime.text"}
			}
		}
	}
	seen := make(map[namedSymbol]int)
	anchors := 0
	unreferenced := !hasStaticSymbolReferences(output)
	for _, sym := range after {
		key, err := artifactSymbolKey(output, sym)
		if err != nil {
			return len(after), anchors, err
		}
		if sym.HasVersion || sym.VersionIndex != 0 || sym.Version != "" || sym.Library != "" {
			return len(after), anchors, errors.New("exported GNU symbol versions must be omitted")
		}
		if originalMarker, exists := markers[sym.Name]; exists && !dynamic {
			address, section, _ := artifactGoMarker(sym, info)
			// The existing writer zeroes marker extent while preserving its
			// source type/binding/visibility. Consumers use the verified table
			// region, not this marker's size. Arbitrary sizes stay forbidden.
			originalShape := originalMarker.Info == sym.Info && originalMarker.Other == sym.Other &&
				(originalMarker.Size == sym.Size || unreferenced && sym.Size == 0) && originalMarker.Section != elf.SHN_UNDEF
			synthesized := unreferenced && sym.Info == byte(elf.STB_GLOBAL)<<4 && sym.Other == 0 && sym.Size == 0
			if sym.Value != address || key.Section != section || !originalShape && !synthesized {
				return len(after), anchors, fmt.Errorf("incorrect Go marker %q", sym.Name)
			}
			delete(markers, sym.Name)
			continue
		}
		bookkeeping := !dynamic && unreferenced && canonicalSectionAnchor(key, output) && canonicalSectionAnchor(key, original)
		if expected[key] > 0 && !bookkeeping && sym.Section > elf.SHN_UNDEF && sym.Section < elf.SHN_LORESERVE {
			owner := output.Sections[sym.Section]
			if source := original.Section(owner.Name); source != nil && !(info != nil && (goSectionName(owner.Name) == ".gopclntab" || owner.Name == ".gofunc")) {
				if source.Addr != owner.Addr || source.Size != owner.Size || source.Flags&^elf.SHF_COMPRESSED != owner.Flags&^elf.SHF_COMPRESSED {
					return len(after), anchors, fmt.Errorf("symbol %q owner range/flags differ from input", sym.Name)
				}
			}
		}
		seen[key]++
		if seen[key] <= expected[key] {
			continue
		}
		if !dynamic && unreferenced && seen[key] == 1 && canonicalSectionAnchor(key, output) {
			// Require source provenance, not merely an internally consistent
			// address in an output that could itself have been corrupted.
			section := original.Section(key.Section)
			if section != nil && section.Addr == sym.Value || info != nil && key.Section == ".gopclntab" && sym.Value == info.Address ||
				info != nil && key.Section == ".gofunc" && len(info.GoFuncData) != 0 && sym.Value == info.GoFuncAddr {
				anchors++
				continue
			}
		}
		return len(after), anchors, fmt.Errorf("symbol %q attributes/address/owner differ from input (dynamic=%v)", sym.Name, dynamic)
	}
	if len(markers) != 0 {
		return len(after), anchors, errors.New("missing Go markers")
	}
	if required || len(after) != 0 {
		for key, count := range expected {
			if seen[key] >= count {
				continue
			}
			if !dynamic && unreferenced && (canonicalSectionAnchor(key, original) || optionalGoAlias(key, info)) {
				continue
			}
			return len(after), anchors, fmt.Errorf("missing source symbol %q (dynamic=%v)", key.Symbol.Name, dynamic)
		}
	}
	return len(after), anchors, nil
}

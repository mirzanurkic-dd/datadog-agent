# symbolcheck

Manual QA tool for the host profiler's symbol export. It exports ELF files the way
the symbol uploader does and checks each exported ELF against its input, not
against another exporter's output. Linux only.

## Build

```sh
bazel build //tools/host-profiler/symbolcheck
```

## Run

```sh
symbolcheck [-objcopy] [-keep DIR] PATH...
```

- `PATH`: an ELF file, or a directory walked for ELF files. Files the profiler
  wouldn't load (non-ELF, relocatable objects) and inputs without symbols are
  skipped; an ELF that can't be opened is a failure.
- `-objcopy`: also check the objcopy export. Like the profiler, it runs objcopy
  with the `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` ambient capabilities, so run
  as root or grant them (for example `--cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH`
  in a container).
- `-keep DIR`: keep exported ELFs in `DIR` instead of deleting them.

The streaming export is always checked. Each check prints one line:

```text
PASS stream /usr/bin/prometheus
FAIL objcopy /usr/lib/libfoo.so: symbol "foo" attributes/address/owner differ from input (dynamic=true)
```

The exit status is 1 if any check fails.

## What is checked

- ELF identity (file header) and retained section payloads, compared after
  decompression.
- Symbols kept for symbolization: names, attributes, addresses and owning
  sections, for static and, when selected, dynamic symbols.
- References that must still resolve: symbol and string-table links,
  relocations and groups.
- Executable `PT_LOAD` ranges covering retained code addresses.
- Go: tables re-parse to the same addresses and bytes as the input. Function
  metadata may re-parse to a prefix of the input's: without the input's
  `runtime.gcbits.*` bound, the parser keeps only the part it uses.
- DWARF: records and line programs are readable, when the input's DWARF is
  readable by Go's `debug/elf`.

Layout, section order and compression encoding may differ from the input.

## Limits

- Like the uploader, a binary whose best symbols are in a separate debug file is
  checked through that debug file.
- A pass means the export preserves what symbolization needs. It does not mean the
  backend indexed it.

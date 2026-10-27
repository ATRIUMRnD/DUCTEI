# qsw-inspect

Field-level decoder and differ for QSW (Qallow Sync Wire) v1/v2 streams. Every byte is labeled with the field it belongs to, and each ENVELOPE body is cross-checked against the real `ductei_qallow` decoder, so this tool never becomes a second source of truth for the layout.

Input: raw binary, hex text, or 0/1 text (auto-detected, override with `--format`). Proto follows the stream's HELLO `proto_ver`, override with `--proto 1|2`.

```powershell
cargo run -q -p conformance-emitter -- "$env:TEMP\v1.bin"
```

```powershell
cargo run -q -p qsw-inspect -- decode "$env:TEMP\v1.bin"
```

```powershell
cargo run -q -p qsw-inspect -- diff "$env:TEMP\v1.bin" "$env:TEMP\v2.bin"
```

```powershell
cargo run -q -p qsw-inspect -- decode --str "00000101 00000000 00000000 00000000 00000000"
```

`--json` gives machine output for both commands. Exit codes: 0 clean/identical, 1 problems/different, 2 usage or I/O error.

Reports: bad magic, unknown proto or frame type, HELLO size, key/blob length mismatches, missing v1 scope shim, truncated frames, trailing bytes, unparsed body bytes, and decoder rejections. CI runs `decode` on the conformance streams when the C conformance check fails.

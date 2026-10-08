# BACcheck

BACcheck reads a BACnet/IP capture (pcap/pcapng), decodes it, and detects the top ~10
network problems a field engineer needs to fix — delivered as a field-engineer-facing
HTML report with prescriptive remediation steps. An interactive TUI is planned for v2.

Design decisions are tracked on the [wayfinder map](https://github.com/xtr3m3b00t3r/bacnetPcapCheck/issues/15).

## Licence

BACcheck is released under the [MIT Licence](LICENSE) — use it, study it, change it,
ship it in whatever you want, no strings. If it helps you, that's what it's for.

This is a personal project, shared to demonstrate engineering craft; it is not a
product or a business.

## Documentation

The site is live at https://xtr3m3b00t3r.github.io/bacnetPcapCheck/, served from the `docs` folder.
Its root `docs/index.html` is the landing page; the manual is a separate self-contained file,
`docs/manual.html`, that also opens offline. Edit the pages in `docs/src/` and the landing page in
`xtask/src/docs.rs`, then run `cargo xtask docs-build`. A test fails when a committed file is
stale. The xtask is dev-only; release builds use `cargo build --release -p baccheck-cli`.

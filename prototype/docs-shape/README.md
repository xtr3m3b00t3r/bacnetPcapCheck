# PROTOTYPE — docs shape (throwaway)

Answers part of wayfinder ticket **#11 — The documentation plan (Diátaxis)**:
*does a Carbon-skinned, Diátaxis-structured docs site read as one product with
the HTML report (ticket #6)?* Not production code — no mdBook, no build step,
no tests.

## Open

```sh
xdg-open docs-carbon.html   # or just open it in a browser
```

A single static HTML file mocking an mdBook-shaped site: left sidebar grouped
into the four Diátaxis quadrants, main pane renders whichever page is
clicked. Same Carbon CDN CSS and header/footer treatment as
`prototype/pdf-report-shape/report-carbon.html`, so the two can be judged
side by side.

Every page listed in the nav is drafted (not just the tutorial) — short,
ASD-STE100 style — so the full v1 page list can be read end to end, not just
imagined from an outline. Two Reference pages (CLI flags, issue catalogue)
are marked **GENERATED** to show what a `cargo xtask docs-gen` fragment
pulled from clap / the library's `IssueSpec` table would look like sitting
inline with hand-written pages.

## The agreed structure this prototype reacts to

Settled by grilling on ticket #11, recorded there in full. Summary:

- **Generator**: mdBook (Rust-native, no Node toolchain, GitHub Pages-friendly).
- **Repo layout**: root-level `docs/` (mdBook's own `book.toml` + `src/`), not a Cargo workspace member.
- **Generation**: a `cargo xtask docs-gen` command writes committed Markdown fragments for the CLI-flags reference (from clap) and the issue catalogue + remediation text (from `IssueSpec`) — never hand-duplicated, so docs can't drift from what the binary/report actually do.
- **Everything else** (Tutorial, How-to, Explanation, and the schema/severity/evidence-floor Reference pages) is hand-authored prose; no generation involved.
- **PDF**: one whole-manual PDF, auto-generated from the same Markdown source, styled with the report's Carbon print CSS (ticket #6) — not hand-maintained separately.
- **rustdoc** (the library crate's Rust API docs) is explicitly out of scope for this site — a separate, contributor-facing artifact.

## Page list (v1)

- **Tutorial** (1): First capture to first report.
- **How-to** (4): Run a capture · Read a finding · Apply a remediation · Interpret severity.
- **Reference** (5): CLI flags (gen) · Issue catalogue (gen) · Finding & Report schema · Severity levels · Evidence-floor semantics.
- **Explanation** (3): How the detectors work · BACnet/IP in brief · Why evidence floors exist.

## Question to answer

Does this look, structure, and page list stand as the ticket #11 resolution,
or does anything need to change before it's recorded and #12 (the docs
static site) is unblocked?

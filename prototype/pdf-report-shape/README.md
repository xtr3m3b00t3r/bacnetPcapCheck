# PROTOTYPE — PDF report shape (throwaway)

Answers wayfinder ticket **#6 — The PDF report shape**: *what does the delivered
field-engineer PDF look like?* Not production code. No tests, no error handling
beyond what makes it run.

## Run

```sh
cargo run
```

Writes three PDFs to `out/` — same fake `Report` (10 findings matching the
Finding schema from ticket #3), three structurally different documents:

| File | Shape | Reads like |
|---|---|---|
| `out/report-a-sections.pdf` | **Section per finding** — summary page (capture facts + severity-ranked issue table), then a deep-dive section per finding: affected devices, evidence + frame refs, numbered remediation steps | Field manual |
| `out/report-b-tables.pdf` | **Table-driven** — one findings matrix (id × severity × affected × count × first/last), then evidence and remediation **appendices keyed by issue id** | Dense reference sheet |
| `out/report-c-devices.pdf` | **Device-centric** — a severity-ordered fix list with checkboxes up front, then everything-to-do grouped per device, network-wide findings last | Work order |

The capture-health warning box (>50% undecodable, per the Finding schema) is
implemented but does not render — the fake capture is healthy. Raise
`CAPTURE.undecodable_pct` above 50 in `src/main.rs` to see it.

## Also trialling: the PDF library

All three variants are rendered with **genpdf 0.2** (the crate surfaced at
charting; `printpdf` is its low-level foundation). Verdict so far:

- genpdf gives a real layout engine (wrapping paragraphs, weighted tables,
  page headers, A4) from pure Rust — raw printpdf would mean hand-placing
  every line.
- Frustrations met: **no cell background colours** (severity chips are coloured
  text, not filled badges), **no repeating table header rows**, `TableLayout`
  rows must match column count exactly, paragraph API is a bit stringly.
- A maintained fork lineage exists (`numaelis-rckive-genpdf` 0.4.x) that may
  have grown some of these — worth a check before locking the decision.

## Question to answer

Which shape (or hybrid — e.g. "A's summary page + C's fix list") does the
delivered PDF follow, and does genpdf stand as the library?

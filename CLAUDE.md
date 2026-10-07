Detector rules are decided in issue #4 (`gh issue view 4 --comments`). Read your detector's numbered rule, and every later "settled reading" comment for it, before writing tests. Fetch your ticket with `gh issue view N --json title,body,comments`. Where the ticket and the rule disagree, the settled reading wins; where neither settles it, stop and ask.

Detector work: read the Detectors and Tests sections of `CODING_STANDARDS.md` before proposing a reading or writing tests. Check any proposed reading against both. The detector seam is agreed; do not ask again.

When a rule's text is ambiguous or incomplete, stop and ask. Propose a full reading (exchange key, close events, window, segmented frames, ratio denominator, floor, severity) in one question. Record the settled reading as a comment on issue #4.

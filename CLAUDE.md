Detector rules are decided in issue #4 (`gh issue view 4 --comments`). Read your detector's numbered rule, and every later "settled reading" comment for it, before writing tests. Fetch your ticket with `gh issue view N --json title,body,comments`. Where the ticket and the rule disagree, the settled reading wins; where neither settles it, stop and ask.

Detector tests: read the Tests section of `CODING_STANDARDS.md` first. Its detector seam is agreed; do not ask again.

When a rule's text is ambiguous or incomplete, stop and ask. Record the settled reading as a comment on issue #4.

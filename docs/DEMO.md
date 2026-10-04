# SENTINEL demo script (about 2.5 minutes)

Run from the project root. Each `demo N` command uses a fresh database, so results are reproducible.

**0:00 Intro (15 s).** "SENTINEL is a security-operations worker. It investigates an alert, collects evidence with real
tools, records a remediation case, then re-reads that case from the database to verify it. It never trusts a tool's
"success" message on its own."

**0:15 Scenario 1, success (45 s).** `python -m app.main demo 1`
Point out: the alert is chosen from the request ("critical"); the alert's reported manifest `pyproject.toml` does not
exist, so the agent switches to `requirements.txt` (recovery without fault injection); evidence = manifest line plus
source references; duplicate check; create; **separate** `get_remediation_case`; 9 independent checks; `COMPLETED`.

**1:00 Scenario 2, recovery (40 s).** `python -m app.main demo 2`
Case creation fails twice with a temporary error. Show `retry 1/3`, `retry 2/3`, the duplicate re-check before every
retry, then success. Exactly one case exists. Then show the bound: the test `test_10b_bounded_retry_gives_up`.

**1:40 Scenario 3, no fabricated result (30 s).** `python -m app.main demo 3`
Jinja2 is only mentioned in a doc. The first search finds nothing, the agent broadens to docs, classifies `DOC_ONLY`,
creates no case, and reports `PARTIALLY_COMPLETED`, not success. Optionally `demo 4` (ambiguous request asks for
clarification) and `demo 5` (patch request stops at `NEEDS_APPROVAL`).

**2:10 Close (20 s).** `python -m unittest discover -s tests -t .` then `python -m app.main serve` to show the console.

# Weekly review: week of YYYY-MM-DD

**Scope:** PRs #… to #…, canon changes since last note, staging snapshot at HH:MM UTC.

## Verdict

One or two sentences. Is anything merged this week unsafe to ship?

## Findings

| # | Severity | Where | What is wrong | Canon rule | Fix |
|---|---|---|---|---|---|
| 1 | high | PR #…, `file.sql:12` | | §… | |
| 2 | medium | staging, `public.table` | | §… | |

Severity: **high** blocks production, **medium** fix before the next deep
review, **low** worth doing.

## Canon

- Changes that conflict with existing rules or with what was merged.
- Rules that the code keeps breaking, which may mean the rule is unclear.

## Audit delta

New or resolved rows from `audit/audit.sql` since last week.

## Open from previous notes

| # | Raised | Status |
|---|---|---|

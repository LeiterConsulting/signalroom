# Release-candidate acceptance

SignalRoom treats release readiness as source-bound evidence. A build is not ready because the interface appears
complete or because one test command passed previously. The acceptance receipt must match the exact current source
digest, include a named viewport review, and record successful lint, JavaScript syntax, and full test-suite runs.

Run the final gate from the repository root:

```powershell
signalroom-release-check --full --reviewer "Reviewer name" --ui-review "Reviewed Settings and primary workflows at desktop and compact widths; verified section navigation, disclosure cues, contrast, focus, and readable content."
```

The command writes `data/release_candidate_receipt.json`. This local receipt is deliberately excluded from Git but
visible in Setup → **Release readiness**. Any source, test, documentation, installer, or deployment-file change
changes the digest and blocks promotion until the full gate runs again.

## Automated interface contract

The static gate blocks when any of these contracts fail:

- all nine Settings areas have one ordered navigation target and a scroll-aware header identity;
- no Settings section exceeds 32 visible controls without being split or progressively disclosed;
- every Settings input, select, and text area has an accessible name, and document IDs are unique;
- every disclosure has a summary plus visible expanded/collapsed and keyboard-focus indicators;
- the root type scale is 16 px, no declared text is below 12 px, the system font stack is retained, and compact
  responsive behavior exists;
- critical semantic foreground/background pairs meet WCAG AA 4.5:1;
- shipped interface assets contain no unfinished markers, debug surfaces, development-only labels, placeholder
  implementation claims, or vague “click here” instructions;
- declared interface functions and undecorated source-level backend functions have an explicit call, registration,
  or packaged entry point.

Automated contrast checks protect the critical semantic palette, not every possible runtime composition. The named
viewport review remains required to catch clipping, layering, focus order, density, misleading hierarchy, and
content-dependent contrast that static parsing cannot prove.

## Function-ownership policy

An unreferenced function is not deleted automatically. The gate lists its file, line, and name under the
`function-ownership` follow-up slice so its intended owner can choose one of three explicit outcomes: wire it into a
real workflow, move it into a named future slice with an acceptance criterion, or remove it with regression
coverage. This keeps uncertain code from being silently discarded or indefinitely ignored.

The current inventory has no unassigned candidates. The heuristic covers declared browser functions, top-level
browser arrow functions, and undecorated source-level Python functions. Decorated API handlers are registrations;
class methods are reviewed through their owning service and tests rather than guessed from name frequency.

## Remaining release-candidate slices

1. **Upgrade and installer matrix** — clean install, in-place upgrade, Windows/Linux launch, Docker Compose,
   localhost/LAN binding, optional model installation, rollback, and retained-data compatibility.
2. **Operational recovery and multi-instance acceptance** — encrypted backup/restore drills, stale identity and
   tenant-route failure cases, unavailable secondary Splunk behavior, authorization boundaries, and long-running
   progress/cancellation UX.

Neither slice may weaken the source-bound UI gate. New orphan candidates or interface regressions appear as named
blockers and are assigned to one of these slices or a newly documented successor.

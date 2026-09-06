# SignalRoom user guide

SignalRoom is organized around security outcomes rather than its underlying services. You do not need to
understand MCP, retrieval pipelines, model routing, or every governance control before beginning an investigation.

## The shortest useful mental model

1. **Investigate** asks a question and shows the evidence and tool activity behind the answer.
2. **Discovery** learns what the selected Splunk instance can see and turns that into reusable context.
3. **Cases** preserve meaningful work, ownership, uncertainty, and decisions across shifts.
4. **Detections** turn completed validation evidence into reviewed, versioned detection content.
5. **Knowledge** controls the local evidence SignalRoom can retrieve again.
6. **Models** shows whether local AI capabilities are ready and provides a governed path for improving them.

The Splunk scope selector in the header is the data boundary. Always confirm it before running or preserving work.

## Guided view and full workspace

SignalRoom starts in **Guided view**. Each page explains its purpose, presents a three-step recommended flow, and
states what an engineer, lead, and executive should expect from it. Complex operational workspaces are summarized
as clearly named additional capabilities.

Select **Show all tools** to reveal the complete page. Selecting an additional capability also reveals the full
workspace and moves directly to that tool. Select **Use guided view** to return to the outcome-focused page.
The preference is stored only in that browser.

This is presentation only. Guided view does not change permissions, routing, stored data, safety gates, model
policy, or API/MCP capability. Nothing is deleted or disabled.

Settings follows the same pattern:

- The default guided setup shows Splunk, Instances, and Models.
- **Platform administration** reveals Repository, Access, Recovery, Workload, Agent, and Release controls.
- Opening a direct link to an administrative section automatically reveals the full settings workspace.

## Where each role should start

| Need | Start here | Immediate value |
|---|---|---|
| Investigate an alert or unusual activity | Investigate | Evidence-backed answer, bounded tool activity, and next actions |
| Understand visibility or posture | Discovery | Coverage, prioritized gaps, changes, and reusable context |
| Coordinate or hand off work | Cases | Owner, severity, evidence health, decisions, and timeline |
| Improve a detection | Detections | Evidence-linked SPL, exact-version review, and safe handoff |
| Improve organizational answers | Knowledge | Curated runbooks, intelligence, references, and known-good SPL |
| Operate or improve local AI | Models | Runtime health, artifact trust, staged evaluation, promotion, and rollback |

### Engineer or analyst

Begin in Investigate. Choose the closest role and outcome from the prompt tree, review the staged prompt, and
submit it. Use Discovery before broad exploratory searches so SignalRoom can reuse retained context. Preserve
material findings in a case instead of leaving them only in conversation history.

### Create and try context-grounded SPL safely

The composer shows whether **SPL context** is ready for the selected connection. When you ask SignalRoom to create
SPL, a local model proposes typed search intent rather than free-form query text. The SPL Context Engine resolves
that intent against indexes, sourcetypes, fields, and knowledge relationships from the exact discovery revision,
then emits bounded SPL through an allowlisted deterministic compiler. Unknown identifiers are withheld instead of
guessed. Run or refresh Standard Discovery if the indicator says **discovery needed**.

Pasted event-shaped examples are replaced with deterministic synthetic shapes before the authoring model sees
them. Field names and types may be retained; source values, `_raw`, evidence excerpts, and tool-result values are
not part of the SPL-authoring packet. This is an authoring boundary, not permission to train a model on Splunk
data.

When an answer contains one or more SPL blocks, Investigate offers **Try this SPL in Splunk**. If the answer
contains several searches, the action opens a chooser instead of guessing which block you meant. Each entry
explains its purpose and expected result, shows the complete SPL, names the exact Splunk scope and bounds, and
opens a trust receipt showing its origin, discovery revision, data-exposure contract, passed checks, and pending
checks.

SignalRoom analyzes read-only safety, workload policy, and retained-result reuse for every block. Choosing a
search creates an editable validation draft; it does not execute the SPL. Review or change the contract, save it,
then choose **Validate with Splunk**. SignalRoom checks the exact target for a native parser without running the
search. You can also opt into a Splunk AI Assistant critique when that instance advertises one; only the SPL and
bounds are sent, never event rows. A parser pass, unavailable parser, or inconclusive response is stated plainly.
The optional critique does not change the query. Then explicitly approve and run it through the validation queue.
Unsafe blocks remain visible with their blocking
reason but cannot be staged. An exact query that already ran for the response is labeled **already executed** so
the interface does not encourage an unnecessary repeat search. **Context compiled** means trusted for review;
Splunk parser validation where available and an approved bounded run are still required before the query is trusted
as executed. The preserved result also shows whether returned field names and types matched the typed intent. Zero
rows are reported as inconclusive rather than falsely proving the expected shape.

### Team lead or incident lead

Begin with the current case or the latest Discovery findings. Review evidence quality, ownership, gaps, and the
next decision. Use the full Discovery workspace when you need run history, estate comparison, continuous
assurance, or the validation queue.

### Executive or CISO

Begin in Investigate with **Security leader / CISO**, or review a case summary. Ask for material risk, confidence,
ownership, and decisions. Discovery inventory and model traces remain available, but the useful output should be a
decision-ready brief rather than a tour of implementation details.

## A safe first session

1. Open **Settings → Splunk** and run connection diagnostics.
2. Confirm the intended Splunk scope in the page header.
3. Open Discovery and run **Standard** discovery.
4. Review prioritized findings and open one in Investigate.
5. Preserve a material observation or hypothesis in a case.
6. Open Models and check whether runtime, artifact trust, and publisher currency are healthy.

Demo mode is optional and synthetic. It is useful for learning the workflow, but it is never silently substituted
for a live Splunk connection.

## Terms used in the interface

| Term | Meaning |
|---|---|
| Evidence | A source-bound observation or retained item that can support analysis |
| Finding | A prioritized discovery observation; not automatically a confirmed incident |
| Knowledge | The tenant-scoped local library used by retrieval; formerly labeled Context |
| Validation | A bounded read-only SPL proposal that requires review before execution |
| Case | A durable investigation record with ownership, timeline, evidence, and decisions |
| Model profile | A task-specific model configuration, not a claim that the model is trusted |
| Candidate | A non-routed local model profile available only to evaluation workflows |
| Promotion | An explicit, evidence-backed change to active model routing or another governed state |

## When to use the full workspace

Use **Show all tools** when you need operational history, cross-instance comparison, continuous assurance,
destination delivery, model supply-chain approval, organization evaluation suites, tournaments, MLTK inventory,
or release administration. These are intentionally available without competing with the first action on every
page.

For deployment and host operations, see [DEPLOYMENT.md](DEPLOYMENT.md). For model behavior, see
[MODEL_ORCHESTRATION_TLDR.md](MODEL_ORCHESTRATION_TLDR.md). For security boundaries, see
[SECURITY.md](SECURITY.md).

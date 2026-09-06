# Cisco and Splunk model catalog review

Last reviewed: **2026-09-05**

This document records what SignalRoom found in the first-party Cisco AI and Foundation AI model catalogs, what
the application actually uses, and why a published model is or is not exposed to analysts. It is a dated intake
record, not a promise that a remote publisher repository will never change. Use **Models → Check for updates**
to compare installed artifacts with current immutable Hugging Face revisions without downloading anything.
SignalRoom's code-owned intake manifest binds every reviewed repository name to its exact reviewed revision,
declared pipeline, access state, license metadata, disposition, and bounded purpose. A repository that changes
in place therefore returns to review even when its name remains unchanged.

The guided Models page shows readiness, configured profiles, and safe local staging first. Select **Show all
tools**, or the named **Artifact trust**, **Evaluation suites**, **Model tournament**, **Promotion gate**,
**Analyst outcome scores**, **Splunk MLTK inventory**, or **Publisher candidates** link, to reach the complete
lifecycle workspace. This changes presentation only; model admission and routing rules are identical.

## Current SignalRoom choices

| Capability | Publisher repository | Observed revision | Decision |
|---|---|---|---|
| Security reasoning | `fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF` | `4a04f7b19513ff9f672169b8fe4288000ab87b07` | Current default security specialist through Ollama |
| Security instruction following | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | `0b58da4736f799f3cb5bbaffb8a39025f1c4e5df` | Current optional instruction-focused specialist through Ollama |
| Security retrieval | `cisco-ai/SecureBERT2.0-biencoder` | `b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0` | Current local embedding specialist |
| Evidence reranking | `cisco-ai/SecureBERT2.0-cross_encoder` | `960b9235bd165911babab7d312fc7f252cdc9d6d` | Current local cross-encoder specialist |
| Entity extraction | `cisco-ai/SecureBERT2.0-NER` | `792db5b533118afee8c3fab86db119d09ab77ff6` | Current local NER specialist |
| Code review prioritization | `cisco-ai/SecureBERT2.0-code-vuln-detection` | `f260674279f97f85d75be257defa62484aa0239c` | Current opt-in bounded local preview |
| Time-series forecasting | `cisco-ai/cisco-time-series-model-1.0` | `038831104abace772bd50bffe76da0c77c364c51` | Current dedicated local/private service |

The revisions above were observed from the publishers' Hugging Face APIs on the review date. SignalRoom does not
treat this table as runtime trust: downloaded artifacts still need their local manifest, digest, immutable
revision, and—when enforcement is enabled—an operator-signed model approval.

### Supersession decisions

- `cisco-ai/cisco-time-series-model-1.0-preview` is superseded by
  [`cisco-ai/cisco-time-series-model-1.0`](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0).
  SignalRoom already uses the 1.0 checkpoint and pins the observed revision in the bundled service.
- Foundation-Sec Reasoning and Foundation-Sec 1.1 Instruct serve different routed jobs. The newer Instruct name
  does not supersede the reasoning specialist for hypothesis generation and security analysis.
- The four SecureBERT 2.0 task heads remain useful specialists; the general SecureBERT base checkpoint does not
  replace their task-specific contracts.

## New candidate: Antares 1B

[`fdtn-ai/antares-1b`](https://huggingface.co/fdtn-ai/antares-1b), observed at revision
`10417eb35641b32e7141157db19c76eb545193b6`, is a small agentic model for vulnerability localization in source
repositories. That maps to SignalRoom's detection-engineering and incident-follow-up mission more directly than
another generic chat model. It is deliberately **not** a configured profile yet.

Admission requires all of the following:

1. Explicit handling for its gated publisher access and license acknowledgement, followed by immutable revision
   pinning, safetensor-only download validation, a local digest, and the existing operator approval policy.
2. A dedicated read-only repository adapter. Inputs must be immutable snapshots; permitted operations must be
   bounded equivalents of file listing, search, and file reads—not a general shell—with no network or write path.
3. A complete tool transcript, evidence-linked candidate paths, limits, confidence, and a SARIF-compatible export.
   Candidate files are review priorities, never vulnerability findings.
4. A SignalRoom benchmark containing representative vulnerable and clean repositories, false-positive and
   file-localization measures, hard time/tool budgets, escape tests, and analyst disposition.
5. An explicit opt-in workflow. Antares must not receive Splunk credentials, be called by ordinary chat or
   Discovery routing, modify a repository, or initiate remediation.

The related 350M Antares checkpoint remains observable but is not a separate integration target until the 1B
workflow is benchmarked and a resource-constrained deployment case justifies comparing it.

## Reviewed but not adopted

- Cisco PASE and STU-PASE are audio representation/speech models. SignalRoom has no bounded security workflow
  whose value justifies ingesting analyst audio.
- Cisco Mini-BART G2P performs grapheme-to-phoneme conversion. It does not improve Splunk investigation,
  retrieval, detection engineering, or evidence handling.
- A base SecureBERT checkpoint is valuable for downstream training, but the current product needs reproducible
  inference contracts, so it continues to use the publisher's task-specific heads.
- No separate first-party Splunk Hugging Face publisher catalog was found during this review; Splunk-associated
  models relevant here are published through Cisco AI or Foundation AI at Cisco.

## Ongoing review contract

- The in-app update check remains read-only and observes every configured Hugging Face source plus every evaluated
  candidate. It follows publisher pagination for the public `cisco-ai` and `fdtn-ai` catalogs and flags new IDs,
  missing reviewed IDs, incomplete inventories, and changes to the reviewed revision, task, access state, or
  declared license. It never downloads, swaps, loads, or approves a model.
- **Stage intake review** creates only a durable local checklist bound to the currently observed source revision.
  It grants no runtime, download, routing, approval, or license authority and can be removed from the queue.
- A remote revision change is drift, not an automatic upgrade. Re-run the relevant evaluation, inspect the model
  card and license, then approve the new exact artifact deliberately.
- Revisit the Cisco AI and Foundation AI publisher catalogs before a release candidate and at least quarterly.
- Record a new dated review here when a candidate, supersession, license, access, runtime, or routing decision
  changes.

Primary publisher sources:

- [Foundation-Sec 8B Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning)
- [Foundation-Sec 1.1 8B Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)
- [Cisco SecureBERT 2.0](https://github.com/cisco-ai-defense/securebert2)
- [Cisco Time Series Model 1.0](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0)
- [Antares 1B](https://huggingface.co/fdtn-ai/antares-1b)

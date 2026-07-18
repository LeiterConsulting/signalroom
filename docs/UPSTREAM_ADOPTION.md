# Upstream adoption map

The upstream Splunk Discovery Tool was reviewed as a source of proven patterns. SignalRoom intentionally adopts concepts, not its monolithic implementation.

| Upstream pattern | SignalRoom treatment |
|---|---|
| Purposeful discovery phases | Smaller read-only pipeline with security coverage scoring |
| Stable blueprint / brief / runbook artifacts | JSON blueprint plus Markdown operator brief, indexed automatically |
| MCP tool aliases | Central logical-to-physical alias registry in `splunk/mcp_client.py` |
| Managed RAG and SPL library | SQLite FTS5 artifact/chunk store with stable evidence references |
| Encrypted configuration | Non-secret JSON plus separate Fernet vault |
| Deterministic + agentic chat | Deterministic inventory/SPL routes before model synthesis |
| Optional capabilities | Explicit task-bound model profiles |
| Unified workspace | Focused Investigate, Discovery, Context, and Models surfaces |

Deferred upstream capabilities include OIDC/MFA and external identity recovery beyond the implemented optional local RBAC, external token administration, durable workers, PDF/DOCX ingestion, Chroma, browser regression infrastructure, and the broader capability-pack installer. Those belong in later production increments rather than the initial kernel.

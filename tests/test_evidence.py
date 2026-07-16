from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate, ArtifactUpdate


def test_artifact_is_chunked_and_searchable(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    record = store.add(
        ArtifactCreate(
            title="PowerShell hunt",
            content="Detect encoded PowerShell execution using process command line telemetry.",
            kind="runbook",
            tags=["windows", "powershell"],
        )
    )

    results = store.search("encoded powershell telemetry")
    assert results
    assert results[0].id.startswith(record.id + ":")
    assert results[0].title == "PowerShell hunt"


def test_delete_removes_search_results(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    record = store.add(ArtifactCreate(title="Temporary", content="uniqueindicator example", kind="reference"))
    assert store.search("uniqueindicator")
    assert store.delete(record.id)
    assert not store.search("uniqueindicator")


def test_update_preserves_artifact_id_and_rebuilds_search_chunks(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    record = store.add(
        ArtifactCreate(title="Original runbook", content="obsoleteindicator", kind="runbook")
    )
    store.save_embeddings("securebert", [(f"{record.id}:0", [1.0, 0.0])])

    updated = store.update(
        record.id,
        ArtifactUpdate(
            title="Revised runbook",
            content="replacementindicator validation procedure",
            tags=["revised", "revised"],
        ),
    )

    assert updated is not None
    assert updated.id == record.id
    assert updated.title == "Revised runbook"
    assert updated.tags == ["revised"]
    assert not store.search("obsoleteindicator")
    assert store.search("replacementindicator")[0].id == f"{record.id}:0"
    assert store.pending_embeddings("securebert")[0][0] == f"{record.id}:0"
    assert store.update("missing", ArtifactUpdate(title="Nope")) is None


def test_semantic_embeddings_are_stored_and_ranked(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    first = store.add(ArtifactCreate(title="Identity", content="authentication anomaly", kind="runbook"))
    second = store.add(ArtifactCreate(title="Network", content="firewall traffic", kind="runbook"))
    store.save_embeddings("securebert", [(f"{first.id}:0", [1.0, 0.0]), (f"{second.id}:0", [0.0, 1.0])])

    results = store.semantic_search([0.9, 0.1], "securebert")
    assert results[0].title == "Identity"
    assert store.embedding_status("securebert") == {
        "total_chunks": 2,
        "indexed_chunks": 2,
        "pending_chunks": 0,
    }


def test_semantic_candidates_include_chunk_context(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    record = store.add(
        ArtifactCreate(title="Endpoint", content="PowerShell process telemetry", kind="runbook")
    )

    candidates = store.semantic_candidates()

    assert candidates[0].id == f"{record.id}:0"
    assert candidates[0].title == "Endpoint"
    assert candidates[0].excerpt == "PowerShell process telemetry"


def test_overlapping_chunks_and_search_excerpts_do_not_begin_mid_word(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    content = ("Ownership review. " * 60) + "\n\n" + (
        "Security telemetry domains need validation. " * 20
    )
    chunks = store._chunks(content)
    assert len(chunks) == 2
    assert chunks[1].startswith("Ownership review.")

    store.add(ArtifactCreate(title="Coverage", content=content, kind="discovery"))
    result = store.search("telemetry validation")[0]
    assert not result.excerpt.startswith("ership")
    assert len(result.excerpt) <= 605

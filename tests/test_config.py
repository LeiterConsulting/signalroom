from splunk_security_agent.config import ConfigStore
from splunk_security_agent.schemas import SplunkConnection


def test_secrets_are_encrypted_and_redacted(tmp_path):
    store = ConfigStore(tmp_path)
    store.update_secrets(splunk_token="sensitive-token")

    assert store.secret("splunk_token") == "sensitive-token"
    assert b"sensitive-token" not in (tmp_path / "secrets.enc").read_bytes()
    assert store.public_payload()["secrets"]["splunk_token"] is True
    assert "sensitive-token" not in str(store.public_payload())


def test_splunk_tls_verification_can_be_disabled(tmp_path):
    store = ConfigStore(tmp_path)
    settings = store.load()
    settings.splunk = SplunkConnection(
        name="Self-signed lab",
        url="https://splunk-lab.example/services/mcp",
        verify_ssl=False,
    )
    store.save(settings)

    loaded = store.load()
    assert loaded.splunk.verify_ssl is False
    assert loaded.splunk.ca_bundle is None

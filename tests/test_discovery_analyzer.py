from splunk_security_agent.discovery import SecurityDiscoveryAnalyzer


def test_discovery_analyzer_builds_security_posture_and_findings():
    inventory = {
        "indexes": [{"title": "main"}, {"title": "security"}],
        "sourcetypes": [
            {"value": "WinEventLog:Security"},
            {"value": "crowdstrike:events:sensor"},
        ],
        "telemetry_activity": [
            {"sourcetype": "WinEventLog:Security", "totalCount": 2000, "recentTime": 1},
        ],
        "knowledge_objects": {
            "saved_searches": [
                {
                    "name": "Suspicious PowerShell",
                    "app": "security_content",
                    "search": "index=* powershell | stats count",
                    "cron_schedule": "*/5 * * * *",
                    "disabled": False,
                }
            ],
            "alerts": [
                {
                    "name": "Disabled identity alert",
                    "search": "index=security action=failure",
                    "disabled": True,
                }
            ],
            "data_models": [
                {"name": "Endpoint", "disabled": False, "acceleration": '{"enabled": true}'}
            ],
            "macros": [{"name": "security_content_summariesonly"}],
            "lookups": [{"name": "asset_lookup"}],
        },
    }

    result = SecurityDiscoveryAnalyzer.analyze(inventory)
    posture = result["posture"]

    assert posture["detections"]["total"] == 2
    assert posture["detections"]["disabled"] == 1
    assert posture["detections"]["broad_searches"] == ["Suspicious PowerShell"]
    assert posture["data_models"]["accelerated"] == 1
    assert posture["telemetry"]["domains"]["identity"]["status"] == "observed"
    assert posture["telemetry"]["domains"]["network"]["status"] == "gap-to-validate"
    assert any(item["domain"] == "detection-health" for item in result["findings"])
    assert result["tracks"]

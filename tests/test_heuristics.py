"""Tests for repo-level credential-risk heuristics."""

from __future__ import annotations

from phantomcreds.heuristics import analyze_repository
from phantomcreds.models import RepoMetadata

SCAN_DATE = "2026-05-18"


def test_clean_repo_stays_clean(repo_metadata: RepoMetadata) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={"README.md": "# normal tool\nThis is a normal integration client.\n"},
        discovery_sources={"provider-relay-posture"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "clean"
    assert report.action == "watch"
    assert findings == []


def test_overt_harvest_posture_becomes_report_only(repo_metadata: RepoMetadata) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "README.md": (
                "No API key needed.\n"
                "Multi-account relay with auth file import.\n"
                "Shared subscription top-up support.\n"
            ),
            "internal/auth/codex/token.go": (
                "func (ts *CodexTokenStorage) SaveTokenToFile(authFilePath string) error {\n"
                '  refresh_token := "secret"\n'
                "  return nil\n"
                "}\n"
            ),
        },
        discovery_sources={"shared-subscription-posture", "token-serialization"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "watchlist"
    assert report.action == "report_only"
    assert {finding.finding_type for finding in findings} == {
        "harvest_posture",
        "credential_persistence",
    }


def test_fixable_management_findings_trigger_issue_filing(repo_metadata: RepoMetadata) -> None:
    files = {
        "internal/store/objectstore.go": (
            "// Files are mirrored to a local workspace so existing file-based flows continue to operate.\n"
            'authDir := filepath.Join(absRoot, "auths")\n'
        ),
        "internal/store/postgresstore.go": (
            "// while mirroring data to a local workspace so existing file-based workflows continue to operate.\n"
            'authDir := filepath.Join(absSpool, "auths")\n'
        ),
        "internal/logging/request_logger.go": (
            "payload := homeRequestLogPayload{\n"
            "  Headers: cloneHeaders(headers),\n"
            "}\n"
            "return l.forwardRequestLogToHome(context.Background(), requestHeaders, buf.String())\n"
        ),
        "internal/logging/request_logger_home_test.go": (
            '"Authorization": {"Bearer secret"},\n'
            't.Fatalf("headers.authorization = %+v, want Bearer secret", got.Headers["Authorization"])\n'
        ),
        "internal/api/modules/amp/routes.go": (
            "func wrapManagementAuth(auth gin.HandlerFunc, prefixes ...string) gin.HandlerFunc {\n"
            'authWithBypass = wrapManagementAuth(auth, "/threads", "/auth", "/docs", "/settings")\n'
            'engine.GET("/threads", append(rootMiddleware, proxyHandler)...)\n'
        ),
        "internal/api/server.go": (
            "engine.Use(corsMiddleware())\n"
            'mgmt := s.engine.Group("/v0/management")\n'
            'c.Header("Access-Control-Allow-Origin", "*")\n'
        ),
    }
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files=files,
        discovery_sources={"raw-auth-forwarding", "auth-bypass", "management-cors"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "high_risk"
    assert report.action == "file_issue"
    assert report.issue_worthy_count >= 3
    assert {finding.finding_type for finding in findings} >= {
        "local_secret_mirror",
        "raw_auth_forwarding",
        "management_auth_bypass",
        "wildcard_management_cors",
    }


def test_exposed_secret_triggers_issue_filing_even_with_harvest_posture(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "README.md": "No API key needed.\nShared subscription relay.\n",
            ".env": 'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n',
        },
        discovery_sources={"shared-subscription-posture"},
        scan_date=SCAN_DATE,
    )
    assert report.action == "file_issue"
    assert "exposed_secret" in {finding.finding_type for finding in findings}
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert exposed.issue_worthy is True
    assert "REDACTED" in exposed.evidence[0]
    assert "abcdefghijklmnopqrstuvwxyz123456" not in exposed.evidence[0]


def test_exposed_secret_detects_cloud_keys_and_private_key_blocks(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.production": (
                'AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n'
                'AWS_SECRET_ACCESS_KEY="abcdEFGHijklMNOPqrstUVWXyz0123456789+/="\n'
                'GOOGLE_API_KEY="AIzaSyA123456789012345678901234567890123"\n'
            ),
            "deploy/id_rsa": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ),
            "gcp-service-account.json": (
                "{\n"
                '  "type": "service_account",\n'
                '  "private_key": "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n"\n'
                "}\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    assert "exposed_secret" in {finding.finding_type for finding in findings}
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    joined = "\n".join(exposed.evidence)
    assert "AKIA1234567890ABCDEF" not in joined
    assert "AIzaSyA123456789012345678901234567890123" not in joined
    assert "OPENSSH PRIVATE KEY" in joined
    assert "GCP service account private key block" in joined


def test_exposed_secret_scans_txt_files_and_additional_ai_keys(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "notes/ops.txt": (
                "OPENROUTER_API_KEY=sk-or-v1-abcdefghijklmnopqrstuvwxyz123456\n"
                "GROQ_API_KEY=gsk_abcdefghijklmnopqrstuvwxyz123456\n"
                "REPLICATE_API_TOKEN=r8_abcdefghijklmnopqrstuvwxyz123456\n"
                "PERPLEXITY_API_KEY=pplx-abcdefghijklmnopqrstuvwxyz123456\n"
                "AWS_SESSION_TOKEN=abcdEFGHijklMNOPqrstUVWXyz0123456789+/abcdEFGHijklMNOPqrstUVWXyz0123456789+/==\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert len(exposed.evidence) == 5
    assert "5 redacted secret indicators" in exposed.summary
    joined = "\n".join(exposed.evidence)
    assert "sk-or-v1-abcdefghijklmnopqrstuvwxyz123456" not in joined
    assert "gsk_abcdefghijklmnopqrstuvwxyz123456" not in joined
    assert "r8_abcdefghijklmnopqrstuvwxyz123456" not in joined
    assert "pplx-abcdefghijklmnopqrstuvwxyz123456" not in joined


def test_redacted_secret_examples_do_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "README.md": (
                "```json\n"
                "{\n"
                '  "evidence": [\n'
                '    ".env:1 - OPENAI_API_KEY=[REDACTED:sk-pro...3456]",\n'
                '    "deploy/id_rsa:1 - [REDACTED:-----BEGIN OPENSSH PRIVATE KEY-----]"\n'
                "  ]\n"
                "}\n"
                "```\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_callback_exposure_detected(repo_metadata: RepoMetadata) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "docker-compose.yml": 'ports:\n  - "8317:8317"\n  - "8085:8085"\n',
            "internal/api/handlers/management/auth_files.go": 'addr := fmt.Sprintf("0.0.0.0:%d", port)\n',
            "internal/auth/codex/oauth_server.go": 'Addr:         fmt.Sprintf(":%d", s.port),\n',
        },
        discovery_sources={"callback-exposure"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "watchlist"
    assert any(finding.finding_type == "callback_exposure" for finding in findings)

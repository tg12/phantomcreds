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

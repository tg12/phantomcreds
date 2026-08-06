"""Tests for repo-level credential-risk heuristics."""

# pylint: disable=missing-function-docstring
# pylint: disable=use-implicit-booleaness-not-comparison
# pylint: disable=line-too-long

from __future__ import annotations

from phantomcreds.heuristics import analyze_repository
from phantomcreds.models import RepoMetadata

SCAN_DATE = "2026-05-18"

# Fabricated AWS credential fixtures, concatenated at runtime. Written as single
# literals they match GitHub's own push-protection pattern, which then blocks pushes to
# this repository even though the values were never issued by AWS.
FAKE_AWS_KEY_ID = "AKIA" + "3FKQZ7XN2WYVJ4TQ"
FAKE_AWS_SECRET = "hV7pQ2xNmR9dLzK4wYb8TfE6" + "uJc1sA3gXn5ZoP0q"


def test_clean_repo_stays_clean(repo_metadata: RepoMetadata) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={"README.md": "# normal tool\nThis is a normal integration client.\n"},
        discovery_sources={"provider-relay-posture"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "clean"
    assert report.action == "watch"
    assert not findings


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


def test_exposed_secret_with_overt_harvest_posture_becomes_report_only(
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
    assert report.action == "report_only"
    assert "exposed_secret" in {finding.finding_type for finding in findings}
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert exposed.issue_worthy is True
    assert "REDACTED" in exposed.evidence[0]
    assert "abcdefghijklmnopqrstuvwxyz123456" not in exposed.evidence[0]


def test_exposed_secret_without_overt_harvest_triggers_issue_filing(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "README.md": "Local development helper.\n",
            ".env": 'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n',
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    assert "exposed_secret" in {finding.finding_type for finding in findings}


def test_exposed_secret_detects_real_keys_inside_env_example_files(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.example": 'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n',
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert ".env.example:1 - OPENAI_API_KEY=[REDACTED:" in exposed.evidence[0]


def test_exposed_secret_ignores_placeholder_keys_inside_env_example_files(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.example": 'OPENAI_API_KEY="your-openai-key-here"\n',
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert not findings


def test_exposed_secret_ignores_provider_placeholder_keys_inside_env_templates(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.docker-example": 'OPENAI_API_KEY="sk-YOUR_OPENAI_API_KEY"\n',
            ".env.developer-example": 'ANTHROPIC_API_KEY="sk-ant-YOUR_ANTHROPIC_API_KEY"\n',
            "deploy/.env.template": 'OPENROUTER_API_KEY="sk-or-v1-YOUR_OPENROUTER_API_KEY"\n',
            "ops/.env.sample": 'DEEPSEEK_API_KEY="sk-YOUR_DEEPSEEK_API_KEY"\n',
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_exposed_secret_detects_real_provider_keys_inside_variant_env_templates(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.docker-example": ('OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n'),
            "deploy/.env.template": (
                'OPENROUTER_API_KEY="sk-or-v1-abcdefghijklmnopqrstuvwxyz123456"\n'
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    joined = "\n".join(exposed.evidence)
    assert ".env.docker-example:1 - OPENAI_API_KEY=[REDACTED:" in joined
    assert "deploy/.env.template:1 - OPENROUTER_API_KEY=[REDACTED:" in joined
    assert "abcdefghijklmnopqrstuvwxyz123456" not in joined


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
                "OPENROUTER_API_KEY=sk-or-v1-T3xQm9ZwK2vLpN8rHdYb4Ec7uJ\n"
                "GROQ_API_KEY=gsk_T3xQm9ZwK2vLpN8rHdYb4Ec7\n"
                "REPLICATE_API_TOKEN=r8_T3xQm9ZwK2vLpN8rHdYb4Ec7\n"
                "PERPLEXITY_API_KEY=pplx-T3xQm9ZwK2vLpN8rHdYb4Ec7\n"
                "AWS_SESSION_TOKEN=hV7pQ2xNmR9dLzK4wYb8TfE6uJc1sA3gXn5ZoP0qWd2R\n"
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
    assert "sk-or-v1-T3xQm9ZwK2vLpN8rHdYb4Ec7uJ" not in joined
    assert "gsk_T3xQm9ZwK2vLpN8rHdYb4Ec7" not in joined
    assert "r8_T3xQm9ZwK2vLpN8rHdYb4Ec7" not in joined
    assert "pplx-T3xQm9ZwK2vLpN8rHdYb4Ec7" not in joined


def test_sequential_placeholder_tokens_do_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    """Prefix-less patterns must not fire on documentation-shaped values."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "notes/ops.txt": (
                "AWS_SESSION_TOKEN=abcdEFGHijklMNOPqrstUVWXyz0123456789+/abcdEFGH==\n"
                "VERCEL_TOKEN=1234567890abcdef1234567890\n"
                "CF_API_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_prefixless_token_alone_is_recorded_but_not_issue_worthy(
    repo_metadata: RepoMetadata,
) -> None:
    """A high-entropy value under a token-shaped name has no provider signature."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={"deploy/settings.toml": "VERCEL_TOKEN = 'hV7pQ2xNmR9dLzK4wYb8TfE6'\n"},
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert exposed.confidence == "needs_review"
    assert exposed.severity == "medium"
    assert exposed.issue_worthy is False
    assert report.action == "watch"


def test_exposed_secret_detects_netrc_aws_pairs_and_connection_strings(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".netrc": "machine api.acme-corp.io login deploy password super-secret-password\n",
            "infra/credentials": (
                f"aws_access_key_id={FAKE_AWS_KEY_ID}\n"
                f"aws_secret_access_key={FAKE_AWS_SECRET}\n"
            ),
            "config/database.ini": (
                "DATABASE_URL=postgres://scanner:topsecretpass@db.acme-corp.io:5432/app\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    joined = "\n".join(exposed.evidence)
    assert "super-secret-password" not in joined
    assert FAKE_AWS_KEY_ID not in joined
    assert FAKE_AWS_SECRET not in joined
    assert "topsecretpass" not in joined
    assert "machine api.acme-corp.io login deploy password [REDACTED]" in joined
    assert "AWS_ACCESS_KEY_ID=[REDACTED:" in joined
    assert "postgres://scanner:[REDACTED]@db.acme-corp.io:5432/app" in joined


def test_aws_pair_evidence_is_not_double_counted(repo_metadata: RepoMetadata) -> None:
    """The pair detector and the inline detector must not both claim the same line."""
    _report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "infra/credentials": (
                f"aws_access_key_id={FAKE_AWS_KEY_ID}\n"
                f"aws_secret_access_key={FAKE_AWS_SECRET}\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert len(exposed.evidence) == 2
    assert "2 redacted secret indicators" in exposed.summary


def test_documentation_aws_key_id_does_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    """A sequential key ID next to a digest-shaped value is a doc example, not a leak."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "config/aws.ini": (
                "aws_access_key_id=AKIA1234567890ABCDEF\n"
                "aws_secret_access_key=da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_local_ci_and_documentation_dsns_are_not_confirmed_exposures(
    repo_metadata: RepoMetadata,
) -> None:
    """Ephemeral CI credentials, doc examples, and Compose defaults are not exposures."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".github/workflows/ci.yml": (
                "      DATABASE_URL: postgresql://ci:ci@localhost/ci_unused\n"
            ),
            ".github/workflows/test.yml": (
                "      DATABASE_URL: postgresql://scanner:scanner@localhost:5432/scanner\n"
            ),
            "CLAUDE.md": "Use `postgresql://user:pass@localhost/appdb` for local runs.\n",
            "docker-compose.yml": (
                "      DATABASE_URL: "
                "postgresql://${POSTGRES_USER:-app}:${POSTGRES_PASSWORD:-app}@postgres:5432/app\n"
            ),
        },
        discovery_sources={"secret-path-gemini-env"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_remote_dsn_is_recorded_for_review_but_is_not_issue_worthy(
    repo_metadata: RepoMetadata,
) -> None:
    """A bare scheme://user:password@host shape has no provider-specific structure."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "config/database.ini": (
                "DATABASE_URL=postgres://svcuser:hV7pQ2xNmR9d@db.prod.acme-corp.io:5432/app\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert exposed.confidence == "needs_review"
    assert exposed.issue_worthy is False
    assert report.action == "watch"
    assert "hV7pQ2xNmR9d" not in "\n".join(exposed.evidence)


def test_detector_regex_source_is_not_captured_as_connection_string_evidence(
    repo_metadata: RepoMetadata,
) -> None:
    """Scanning a fork of this project must not treat its own patterns as evidence."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "detectors.py": (
                'PAT = re.compile(r"(?P<dsn>mysql://(?P<user>[^:\\s/@]+):'
                '(?P<password>[^@\\s]+)@(?P<host>[^\\s]+))")\n'
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_env_template_placeholder_connection_string_does_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.example": ("DATABASE_URL=postgres://user:password@localhost:5432/cliproxy\n"),
            "deploy/.env.template": (
                "MONGODB_URL=mongodb://user:password@db.example.com:27017/app\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_env_template_real_connection_string_still_triggers_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".env.example": (
                "DATABASE_URL=postgres://scanner:topsecretpass@db.prod.internal:5432/app\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    assert exposed.confidence == "needs_review"
    assert exposed.evidence[0] == (
        ".env.example:1 - postgres://scanner:[REDACTED]@db.prod.internal:5432/app"
    )


def test_exposed_secret_detects_pypirc_docker_and_terraform_credentials(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".pypirc": (
                "[pypi]\nusername = __token__\npassword = pypi-abcdefghijklmnopqrstuvwxyz123456\n"
            ),
            ".docker/config.json": (
                "{\n"
                '  "auths": {\n'
                '    "https://index.docker.io/v1/": {\n'
                '      "auth": "ZGVwbG95OnN1cGVyLXNlY3JldC1wYXNz"\n'
                "    }\n"
                "  }\n"
                "}\n"
            ),
            "credentials.tfrc.json": (
                "{\n"
                '  "credentials": {\n'
                '    "app.terraform.io": {\n'
                '      "token": "atlasv1abcdefghijklmnopqrstuvwxyz123456"\n'
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "file_issue"
    exposed = next(finding for finding in findings if finding.finding_type == "exposed_secret")
    joined = "\n".join(exposed.evidence)
    assert "pypi-abcdefghijklmnopqrstuvwxyz123456" not in joined
    assert "ZGVwbG95OnN1cGVyLXNlY3JldC1wYXNz" not in joined
    assert "atlasv1abcdefghijklmnopqrstuvwxyz123456" not in joined
    assert "username=__token__" in joined
    assert "password=[REDACTED:pypi-a...3456]" in joined
    assert "auth=[REDACTED:ZGVwbG...YXNz]" in joined
    assert "token=[REDACTED:atlasv...3456]" in joined


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
            "docker-compose.yml": (
                "services:\n"
                "  oauth:\n"
                "    ports:\n"
                '      - "8085:8085"\n'
                "    environment:\n"
                "      OAUTH_CALLBACK_HOST: 0.0.0.0\n"
                "      OAUTH_REDIRECT_URI: http://0.0.0.0:8085/callback\n"
            ),
            "internal/auth/codex/oauth_server.go": (
                'Addr: fmt.Sprintf("0.0.0.0:%d", s.port),\n'
                'redirect_uri := "http://0.0.0.0:8085/callback"\n'
            ),
        },
        discovery_sources={"callback-exposure"},
        scan_date=SCAN_DATE,
    )
    assert report.classification == "watchlist"
    assert any(finding.finding_type == "callback_exposure" for finding in findings)


def test_generic_container_binds_are_not_callback_exposure(repo_metadata: RepoMetadata) -> None:
    """Two unrelated 0.0.0.0 service binds are not a published OAuth callback."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "docker-compose.yml": (
                "services:\n"
                "  api:\n"
                "    environment:\n"
                "      API_HOST: 0.0.0.0\n"
                "  hermes:\n"
                "    expose:\n"
                '      - "9000"\n'
                "    environment:\n"
                "      API_SERVER_HOST: 0.0.0.0\n"
            ),
        },
        discovery_sources={"callback-exposure"},
        scan_date=SCAN_DATE,
    )
    assert report.action == "watch"
    assert "callback_exposure" not in {finding.finding_type for finding in findings}


def test_unpublished_oauth_service_is_not_callback_exposure(repo_metadata: RepoMetadata) -> None:
    """OAuth semantics without a host-port mapping is not an external exposure."""
    _report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "docker-compose.yml": (
                "services:\n"
                "  oauth:\n"
                "    expose:\n"
                '      - "8085"\n'
                "    environment:\n"
                "      OAUTH_CALLBACK_HOST: 0.0.0.0\n"
                "      OAUTH_REDIRECT_URI: http://0.0.0.0:8085/callback\n"
            ),
        },
        discovery_sources={"callback-exposure"},
        scan_date=SCAN_DATE,
    )
    assert "callback_exposure" not in {finding.finding_type for finding in findings}


def test_lone_watchlist_finding_does_not_trigger_issue_filing(
    repo_metadata: RepoMetadata,
) -> None:
    """One watchlist-grade finding is recorded, not escalated to a maintainer."""
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "docker-compose.yml": (
                "services:\n"
                "  oauth:\n"
                "    ports:\n"
                '      - "8085:8085"\n'
                "    environment:\n"
                "      OAUTH_CALLBACK_HOST: 0.0.0.0\n"
                "      OAUTH_REDIRECT_URI: http://0.0.0.0:8085/callback\n"
            ),
        },
        discovery_sources={"callback-exposure"},
        scan_date=SCAN_DATE,
    )
    assert [finding.finding_type for finding in findings] == ["callback_exposure"]
    assert report.classification == "watchlist"
    assert report.issue_worthy_count == 1
    assert report.action == "watch"


def test_non_live_secret_contexts_do_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "tests/test_heuristics.py": (
                'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n'
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "dummy\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ),
            "fixtures/service-account.example.json": (
                "{\n"
                '  "type": "service_account",\n'
                '  "private_key": "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n"\n'
                "}\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert "exposed_secret" not in {finding.finding_type for finding in findings}
    assert report.issue_worthy_count == 0


def test_placeholder_container_credentials_do_not_trigger_exposed_secret(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            ".pypirc": ("[pypi]\nusername = __token__\npassword = your-token-here\n"),
            "credentials.tfrc.json": (
                "{\n"
                '  "credentials": {\n'
                '    "app.terraform.io": {\n'
                '      "token": "placeholder-token-value"\n'
                "    }\n"
                "  }\n"
                "}\n"
            ),
            ".docker/config.json": (
                "{\n"
                '  "auths": {\n'
                '    "https://index.docker.io/v1/": {\n'
                '      "auth": "exampleexampleexample"\n'
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert report.action == "watch"
    assert "exposed_secret" not in {finding.finding_type for finding in findings}


def test_docs_and_query_strings_do_not_trigger_credential_persistence(
    repo_metadata: RepoMetadata,
) -> None:
    report, findings = analyze_repository(
        metadata=repo_metadata,
        files={
            "README.md": (
                "This scanner avoids flagging every repo mentioning token, cookie, or OAuth.\n"
                "The repository documents detection trade-offs rather than unsafe storage.\n"
            ),
            "src/phantomcreds/config.py": (
                '"auth file" OR "session export" OR "cookie login" OR "token store"\n'
                '"use your own session" OR "browser cookies" OR "import cookies"\n'
            ),
        },
        discovery_sources={"auth-import-posture"},
        scan_date=SCAN_DATE,
    )

    assert "credential_persistence" not in {finding.finding_type for finding in findings}
    assert report.finding_count == 0

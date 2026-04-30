from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
import requests

from mc_auto_server_builder.action_preflight import (
    BisectPreflightInput,
    ContinueAfterRestoreModsState,
    assess_adjust_memory,
    assess_bisect_mods,
    assess_change_java,
    assess_continue_after_restore_mods,
    assess_non_mutating_action,
    assess_remove_mods,
)
from mc_auto_server_builder.ai import BuilderAIService
from mc_auto_server_builder.bisect_runtime import (
    build_bisect_feedback_payload,
    build_bisect_round_record,
    derive_bisect_followups,
    make_bisect_progress_token,
    prepare_bisect_round_plan,
    prepare_bisect_session_round_update,
    store_pending_bisect_round_plan,
    summarize_bisect_round_outcome,
    update_bisect_session_after_round,
    update_bisect_session_fields,
)
from mc_auto_server_builder.builder import (
    RemoteFailureDetail,
    RemoveValidationStatePayload,
    ServerBuilder,
    _build_download_failure_detail,
    _normalize_curseforge_file_payload,
)
from mc_auto_server_builder.models import (
    ActionPreflight,
    AIResult,
    BisectMoveRecord,
    BisectRoundRecord,
    BisectSession,
    DetectionCandidate,
    DetectionEvidence,
    PackManifest,
)
from mc_auto_server_builder.recognition import (
    RecognitionFallbackPlan,
    choose_latest_lts_java_version,
)
from mc_auto_server_builder.recognition_runtime import (
    build_ai_context,
    build_recognition_candidates,
    preflight_recognition_plan,
    recognition_runtime_feedback,
    select_next_recognition_plan,
)
from mc_auto_server_builder.reporting import (
    attempt_trace_path,
    build_meta_payload,
    build_recognition_summary,
    generate_report,
    package_server,
    summarize_ai_context,
)
from mc_auto_server_builder.util import (
    DownloadConfig,
    Downloader,
    DownloadError,
    DownloadFailure,
    DownloadTask,
    ExternalDataError,
    ExternalRequestError,
    ExternalResponseError,
    configure_requests_session,
)


@pytest.mark.parametrize(
    ("state", "allowed", "reason"),
    [
        (ContinueAfterRestoreModsState(), False, "no_remove_validation_context"),
        (
            ContinueAfterRestoreModsState(
                continue_allowed=True,
                rollback_snapshot_tag="attempt_1_action_1",
                post_remove_active_mods=["a.jar"],
                continued=True,
                problem_changed=True,
            ),
            False,
            "remove_validation_continue_already_consumed",
        ),
        (
            ContinueAfterRestoreModsState(
                continue_allowed=True,
                rollback_snapshot_tag="attempt_1_action_1",
                post_remove_active_mods=["a.jar"],
                continued=False,
                problem_changed=False,
            ),
            False,
            "remove_validation_problem_not_changed",
        ),
        (
            ContinueAfterRestoreModsState(
                continue_allowed=True,
                rollback_snapshot_tag="attempt_1_action_1",
                post_remove_active_mods=["a.jar"],
                continued=False,
                problem_changed=True,
            ),
            True,
            "remove_validation_continue_allowed",
        ),
    ],
)
def test_action_preflight_continue_after_restore_mods_cases(state, allowed, reason):
    preflight = assess_continue_after_restore_mods(state)
    assert preflight.allowed is allowed
    assert preflight.reason == reason


@pytest.mark.parametrize(
    ("resolved", "regex_targets", "unresolved", "allowed", "reason"),
    [
        (["a.jar", "b.jar"], [], [], True, "resolved_low_volume_mod_removal"),
        ([], [], ["missing.jar"], False, "no_installed_targets_resolved"),
        (["a.jar"], ["regex:.*client.*"], [], False, "regex_remove_requires_manual_review"),
        (["a.jar", "b.jar", "c.jar", "d.jar"], [], [], False, "too_many_mod_targets"),
    ],
)
def test_action_preflight_remove_mods_cases(resolved, regex_targets, unresolved, allowed, reason):
    preflight = assess_remove_mods("remove_mods", resolved, regex_targets, unresolved, rollback_on_failure=False, safe_limit=3)
    assert preflight.allowed is allowed
    assert preflight.reason == reason


@pytest.mark.parametrize(
    ("xmx", "xms", "current", "system", "ratio", "allowed", "reason"),
    [
        ("6G", "4G", 4.0, 16.0, 0.75, True, "bounded_memory_adjustment"),
        ("14G", "8G", 4.0, 16.0, 0.75, False, "memory_plan_exceeds_cap"),
        ("10G", "8G", 4.0, 32.0, 0.75, False, "memory_change_too_large"),
    ],
)
def test_action_preflight_adjust_memory_cases(xmx, xms, current, system, ratio, allowed, reason):
    preflight = assess_adjust_memory("adjust_memory", xmx, xms, current, float(xmx[:-1]), system, ratio)
    assert preflight.allowed is allowed
    assert preflight.reason == reason


@pytest.mark.parametrize(
    ("target", "current", "allowed", "reason"),
    [
        (21, 17, True, "whitelisted_java_switch"),
        (26, 17, False, "unsupported_java_version"),
        (25, 17, False, "java_version_jump_too_large"),
    ],
)
def test_action_preflight_change_java_cases(target, current, allowed, reason):
    preflight = assess_change_java("change_java", target, current)
    assert preflight.allowed is allowed
    assert preflight.reason == reason


@pytest.mark.parametrize(
    ("payload", "allowed", "reason"),
    [
        (
            BisectPreflightInput(
                action_type="bisect_mods",
                bisect_mode="initial",
                request_source="ai",
                resolved_targets=["a.jar", "b.jar", "lib.jar"],
                move_candidates=["lib.jar"],
                next_allowed_requests=[],
                completed_requests=[],
                completed_request_tokens=[],
            ),
            True,
            "controlled_bisect_allowed",
        ),
        (
            BisectPreflightInput(
                action_type="bisect_mods",
                bisect_mode="switch_group",
                request_source="ai",
                resolved_targets=["a.jar", "b.jar"],
                move_candidates=[],
                next_allowed_requests=[],
                completed_requests=[],
                completed_request_tokens=[],
            ),
            False,
            "bisect_request_not_allowed_in_current_state",
        ),
        (
            BisectPreflightInput(
                action_type="bisect_mods",
                bisect_mode="initial",
                request_source="ai",
                resolved_targets=["a.jar", "b.jar"],
                move_candidates=[],
                next_allowed_requests=[],
                completed_requests=[],
                completed_request_tokens=[],
                last_requested_targets=["a.jar", "b.jar"],
            ),
            False,
            "duplicate_bisect_request_after_previous_round",
        ),
    ],
)
def test_action_preflight_bisect_cases(payload, allowed, reason):
    preflight = assess_bisect_mods(payload)
    assert preflight.allowed is allowed
    assert preflight.reason == reason


@pytest.mark.parametrize("action_type", ["stop_and_report", "report_manual_fix"])
def test_action_preflight_non_mutating_cases(action_type):
    preflight = assess_non_mutating_action(action_type)
    assert preflight.allowed is True
    assert preflight.reason == "non_mutating_action"


def test_ai_provider_http_status_errors_use_external_response_error():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        ai=SimpleNamespace(endpoint="http://ai", model="x", timeout_sec=5, max_retries=0, retry_backoff_sec=0.1, enabled=True, debug=False),
        proxy=SimpleNamespace(to_requests_proxies=lambda: {"http": "http://proxy:8080"}, trust_env=False),
    )
    builder._log = lambda *_args, **_kwargs: None
    service = BuilderAIService(builder)

    class Resp:
        status_code = 429
        text = "busy"

        def json(self):
            return {}

    class FakeSession:
        def __init__(self):
            self.proxies = {}
            self.trust_env = True

        def post(self, *_args, **_kwargs):
            return Resp()

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    import mc_auto_server_builder.ai as ai_module

    original_session = ai_module.requests.Session
    try:
        ai_module.requests.Session = FakeSession
        with pytest.raises(ExternalResponseError):
            service._call_ollama_generate("hello")
    finally:
        ai_module.requests.Session = original_session


def test_ai_provider_invalid_json_uses_external_data_error():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        ai=SimpleNamespace(endpoint="http://ai", model="x", timeout_sec=5, max_retries=0, retry_backoff_sec=0.1, enabled=True, debug=False),
        proxy=SimpleNamespace(to_requests_proxies=lambda: None, trust_env=True),
    )
    builder._log = lambda *_args, **_kwargs: None
    service = BuilderAIService(builder)

    class Resp:
        status_code = 200
        text = "oops"

        def json(self):
            raise ValueError("bad json")

    class FakeSession:
        def __init__(self):
            self.proxies = {}
            self.trust_env = True

        def post(self, *_args, **_kwargs):
            return Resp()

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    import mc_auto_server_builder.ai as ai_module

    original_session = ai_module.requests.Session
    try:
        ai_module.requests.Session = FakeSession
        with pytest.raises(ExternalDataError):
            service._call_ollama_generate("hello")
    finally:
        ai_module.requests.Session = original_session


def test_ai_provider_retries_retryable_external_request_error_and_stops_on_data_error():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        ai=SimpleNamespace(
            endpoint="http://ai",
            model="x",
            timeout_sec=5,
            max_retries=2,
            retry_backoff_sec=0.0,
            enabled=True,
            debug=False,
            provider="ollama",
        ),
        proxy=SimpleNamespace(to_requests_proxies=lambda: None, trust_env=True),
    )
    debug_logs: list[str] = []
    builder._log = lambda *_args, **_kwargs: None
    service = BuilderAIService(builder)
    service._ai_debug = debug_logs.append

    class Resp:
        status_code = 200
        text = "ok"

        def json(self):
            return {"response": "done"}

    import mc_auto_server_builder.ai as ai_module

    calls = {"count": 0}
    original_session = ai_module.requests.Session
    original_sleep = ai_module.time.sleep
    try:
        class FakeSession:
            def __init__(self):
                self.proxies = {}
                self.trust_env = True

            def post(self, *_args, **_kwargs):
                return fake_post()

            def close(self):
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        def fake_post(*_args, **_kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ai_module.requests.ConnectionError("offline")
            return Resp()

        ai_module.requests.Session = FakeSession
        ai_module.time.sleep = lambda *_args, **_kwargs: None

        assert service._call_ollama_generate("hello") == "done"
    finally:
        ai_module.requests.Session = original_session
        ai_module.time.sleep = original_sleep

    assert calls["count"] == 2
    assert any("retryable=True" in item and "ExternalRequestError" in item for item in debug_logs)


def test_ai_provider_does_not_retry_external_data_error():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        ai=SimpleNamespace(
            endpoint="http://ai",
            model="x",
            timeout_sec=5,
            max_retries=2,
            retry_backoff_sec=0.0,
            enabled=True,
            debug=False,
            provider="ollama",
        ),
        proxy=SimpleNamespace(to_requests_proxies=lambda: None, trust_env=True),
    )


def test_configure_requests_session_applies_proxy_settings():
    session = requests.Session()
    try:
        configure_requests_session(
            session,
            proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"},
            trust_env=False,
        )
        assert session.proxies["http"] == "http://127.0.0.1:7890"
        assert session.proxies["https"] == "http://127.0.0.1:7890"
        assert session.trust_env is False
    finally:
        session.close()


def test_builder_request_session_uses_config_proxy():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        proxy=SimpleNamespace(to_requests_proxies=lambda: {"http": "http://proxy:8080"}, trust_env=False)
    )

    with ServerBuilder._create_request_session(builder) as session:
        assert session.proxies["http"] == "http://proxy:8080"
        assert session.trust_env is False


def test_cf_post_json_passes_proxy_to_session():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        curseforge_api_key="token",
        proxy=SimpleNamespace(to_requests_proxies=lambda: {"https": "http://proxy:8443"}, trust_env=False),
    )

    calls: dict[str, object] = {}

    class _FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    class _FakeSession:
        def __init__(self):
            self.proxies: dict[str, str] = {}
            self.trust_env = True

        def post(self, url, **kwargs):
            calls["url"] = url
            calls["kwargs"] = kwargs
            calls["proxies"] = dict(self.proxies)
            calls["trust_env"] = self.trust_env
            return _FakeResponse()

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    import mc_auto_server_builder.builder as builder_module

    original_session = builder_module.requests.Session
    try:
        builder_module.requests.Session = _FakeSession
        payload = ServerBuilder._cf_post_json(builder, "/v1/mods/files", payload={"ids": [1]})
    finally:
        builder_module.requests.Session = original_session

    assert payload == {"ok": True}
    assert calls["proxies"] == {"https": "http://proxy:8443"}
    assert calls["trust_env"] is False


def test_downloader_download_file_wraps_os_error_without_retry(tmp_path):
    logs: list[tuple[str, str, str]] = []
    logger = SimpleNamespace(
        log=lambda stage, message, level: logs.append((stage, str(level), message)),
        is_download_ui_active=lambda: False,
    )
    downloader = Downloader(DownloadConfig(max_retries=3, retry_backoff_sec=0.0), logger=logger)
    out = tmp_path / "artifact.bin"

    class Resp:
        headers = {"Content-Length": "4"}

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size=0):
            _ = chunk_size
            yield b"data"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class Session:
        def get(self, *_args, **_kwargs):
            return Resp()

        def close(self):
            return None

    original_open = Path.open
    try:
        def broken_open(self, *args, **kwargs):
            if self == out:
                raise OSError("disk full")
            return original_open(self, *args, **kwargs)

        Path.open = broken_open
        with pytest.raises(DownloadError, match="OSError"):
            downloader.download_file("https://example.invalid/file", out, session_factory=Session)
    finally:
        Path.open = original_open

    assert any("下载写入失败" in message and "OSError" in message for _stage, _level, message in logs)


def test_downloader_download_task_continues_after_extract_failure(tmp_path):
    logs: list[tuple[str, str, str]] = []

    class Logger:
        def log(self, stage, message, level):
            logs.append((stage, str(level), message))

        def is_download_ui_active(self):
            return False

        def download_ui_task_started(self, **_kwargs):
            return None

        def download_ui_task_progress(self, **_kwargs):
            return None

        def download_ui_task_total(self, **_kwargs):
            return None

        def download_ui_task_finished(self, **_kwargs):
            return None

    downloader = Downloader(DownloadConfig(max_retries=1, retry_backoff_sec=0.0), logger=Logger())
    task = __import__("mc_auto_server_builder.util", fromlist=["DownloadTask"]).DownloadTask(
        out=tmp_path / "artifact.zip",
        urls=["https://example.invalid/one", "https://example.invalid/two"],
        extract_to=tmp_path / "extract",
    )

    calls: list[str] = []
    original_extract = __import__("mc_auto_server_builder.util", fromlist=["extract_archive"]).extract_archive
    try:
        def fake_download_file(url, out, **_kwargs):
            calls.append(url)
            out.write_bytes(b"zip")
            return out

        def fake_extract(_src, _dst):
            if len(calls) == 1:
                raise zipfile.BadZipFile("broken archive")

        downloader.download_file = fake_download_file
        import mc_auto_server_builder.util as util_module

        util_module.extract_archive = fake_extract
        result = downloader.download_task(task)
    finally:
        import mc_auto_server_builder.util as util_module

        util_module.extract_archive = original_extract

    assert result == task.out
    assert calls == ["https://example.invalid/one", "https://example.invalid/two"]
    assert any("下载任务候选源失败" in message and "BadZipFile" in message for _stage, _level, message in logs)


def test_execute_action_with_safeguards_records_rollback_failure_details():
    import mc_auto_server_builder.builder as builder_module

    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "2G"
    builder.extra_jvm_flags = []
    builder.current_java_version = 17
    builder.current_java_bin = None
    builder.backup_mods = lambda _tag: None
    builder.set_jvm_args = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write denied"))

    original_execute_adjust_memory_action = builder_module.execute_adjust_memory_action
    try:
        builder_module.execute_adjust_memory_action = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write denied"))
        stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
            builder,
            1,
            {"type": "adjust_memory", "xmx_gb": 6, "xms_gb": 3},
            ActionPreflight(action_type="adjust_memory", risk="low", allowed=True, reason="ok"),
            "attempt_1_action_1",
        )
    finally:
        builder_module.execute_adjust_memory_action = original_execute_adjust_memory_action

    assert stop is False
    assert execution["status"] == "failed"
    assert rollback is not None
    assert rollback["performed"] is False
    assert rollback["error"] == "OSError:write denied"
    assert builder.operations[-1] == "action_failed:adjust_memory:OSError:rollback=failed:OSError:write denied"


def _fake_extract_archive_creating_java(dst: Path, binary_name: str = "java") -> None:
    bin_dir = dst / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / binary_name).write_text("java", encoding="utf-8")


def test_download_graalvm17_from_github_uses_release_asset(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        github_api_key="",
        download=SimpleNamespace(connect_timeout=3, read_timeout=5),
    )
    builder.operations = []
    builder.workdirs = SimpleNamespace(java_bins=tmp_path / "java")
    builder.workdirs.java_bins.mkdir(parents=True)
    builder.java_params_mode_by_version = {}
    builder._log = lambda *_args, **_kwargs: None

    download_calls: list[tuple[str, dict[str, str] | None, object]] = []

    builder._download_file = lambda url, out, stage="install.download", headers=None, session_factory=None: download_calls.append(
        (url, headers, session_factory)
    ) or out.write_bytes(b"zip") or out

    import mc_auto_server_builder.builder as builder_module

    original_http_get_json = builder_module.http_get_json
    original_extract = builder_module.extract_archive
    original_normalize = builder_module.normalize_java_home_layout
    try:
        builder_module.http_get_json = lambda url, headers=None, timeout=60: [
            {
                "tag_name": "v1",
                "assets": [
                    {
                        "name": "grallvm17-windows-x64.zip",
                        "browser_download_url": "https://github.com/brokestar233/grallvm17-bin/releases/download/v1/grallvm17-windows-x64.zip",
                    }
                ],
            }
        ]
        builder_module.extract_archive = lambda src, dst: _fake_extract_archive_creating_java(dst)
        builder_module.normalize_java_home_layout = lambda java_home: (java_home, False)

        assert ServerBuilder._download_graalvm17_from_github(builder) is True
    finally:
        builder_module.http_get_json = original_http_get_json
        builder_module.extract_archive = original_extract
        builder_module.normalize_java_home_layout = original_normalize

    assert download_calls == [
        (
            "https://github.com/brokestar233/grallvm17-bin/releases/download/v1/grallvm17-windows-x64.zip",
            None,
            None,
        )
    ]
    assert "graalvm17_selected_asset:grallvm17-windows-x64.zip" in builder.operations
    assert not (builder.workdirs.java_bins / "grallvm17-windows-x64.zip").exists()
    assert not (builder.workdirs.java_bins / "graalvm17-windows-x64.zip").exists()


def test_download_graalvm17_from_github_records_release_fetch_category(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(github_api_key="", download=SimpleNamespace(connect_timeout=3, read_timeout=5))
    builder.operations = []
    builder.workdirs = SimpleNamespace(java_bins=tmp_path / "java")
    builder.workdirs.java_bins.mkdir(parents=True)
    builder._log = lambda *_args, **_kwargs: None

    import mc_auto_server_builder.builder as builder_module

    original_http_get_json = builder_module.http_get_json
    try:
        def _raise(*_args, **_kwargs):
            raise ExternalResponseError("rate limited")

        builder_module.http_get_json = _raise
        assert ServerBuilder._download_graalvm17_from_github(builder) is False
    finally:
        builder_module.http_get_json = original_http_get_json

    assert "graalvm17_release_fetch:response:ExternalResponseError:17" in builder.operations


def test_download_temurin_from_adoptium_records_extract_category(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(download=SimpleNamespace(connect_timeout=3, read_timeout=5))
    builder.operations = []
    builder.workdirs = SimpleNamespace(java_bins=tmp_path / "java")
    builder.workdirs.java_bins.mkdir(parents=True)
    builder.java_params_mode_by_version = {}
    builder._log = lambda *_args, **_kwargs: None
    builder._download_file = lambda *_args, **_kwargs: tmp_path / "java" / "temurin-17.tar.gz"

    import mc_auto_server_builder.builder as builder_module

    original_platform = builder_module.adoptium_platform_triplet
    original_extract = builder_module.extract_archive
    try:
        builder_module.adoptium_platform_triplet = lambda: ("linux", "x64", "tar.gz")
        builder_module.extract_archive = lambda *_args, **_kwargs: (_ for _ in ()).throw(zipfile.BadZipFile("broken"))
        assert ServerBuilder._download_temurin_from_adoptium(builder, 17) is False
    finally:
        builder_module.adoptium_platform_triplet = original_platform
        builder_module.extract_archive = original_extract

    assert "temurin_download_or_extract:extract:BadZipFile:17" in builder.operations


def test_download_dragonwell_from_github_records_release_fetch_category(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(github_api_key="")
    builder.operations = []
    builder.workdirs = SimpleNamespace(java_bins=tmp_path / "java")
    builder.workdirs.java_bins.mkdir(parents=True)
    builder._log = lambda *_args, **_kwargs: None

    import mc_auto_server_builder.builder as builder_module

    original_http_get_json = builder_module.http_get_json
    try:
        def _raise(*_args, **_kwargs):
            raise ExternalRequestError("offline")

        builder_module.http_get_json = _raise
        assert ServerBuilder._download_dragonwell_from_github(builder, 8) is False
    finally:
        builder_module.http_get_json = original_http_get_json

    assert "dragonwell_release_fetch:request:ExternalRequestError:dragonwell8" in builder.operations


def test_download_file_raises_download_error_for_failed_download_task(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.downloader = SimpleNamespace(
        download_files=lambda _tasks: ([], [SimpleNamespace(error="hash_mismatch", task=SimpleNamespace(out=tmp_path / "out.bin"))])
    )

    with pytest.raises(DownloadError, match="下载失败"):
        ServerBuilder._download_file(builder, "https://example.invalid/file", tmp_path / "out.bin")


def test_download_graalvm_from_oracle_keeps_regular_cookie_header_for_java_21(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        download=SimpleNamespace(connect_timeout=3, read_timeout=5),
    )
    builder.operations = []
    builder.workdirs = SimpleNamespace(java_bins=tmp_path / "java")
    builder.workdirs.java_bins.mkdir(parents=True)
    builder.java_params_mode_by_version = {}
    builder._log = lambda *_args, **_kwargs: None

    builder._oracle_fetch_json_with_diag = lambda **kwargs: (
        (
            {
                "group": {
                    "Title": "Oracle GraalVM",
                    "SubTitle": "Oracle GraalVM for JDK 21",
                    "Releases": {"1": {"JSON File": "/release.json"}},
                }
            }
            if kwargs["op_prefix"] == "oracle_graalvm_index"
            else {
                "Packages": {
                    "Core": {
                        "Files": {
                            "oracle-graalvm-linux-x64-21": {
                                "File": "https://download.oracle.com/otn/utilities_drivers/oracle-labs/graalvm21.tar.gz",
                                "Hash": [],
                            }
                        }
                    }
                }
            }
        ),
        "minimal",
    )

    download_calls: list[tuple[str, dict[str, str] | None, object]] = []

    builder._download_file = lambda url, out, stage="install.download", headers=None, session_factory=None: download_calls.append(
        (url, headers, session_factory)
    ) or out.write_bytes(b"tar") or out

    import mc_auto_server_builder.builder as builder_module

    original_platform = builder_module.oracle_platform_triplet
    original_extract = builder_module.extract_archive
    original_normalize = builder_module.normalize_java_home_layout
    try:
        builder_module.oracle_platform_triplet = lambda: ("linux", "x64", "tar.gz")
        builder_module.extract_archive = lambda src, dst: _fake_extract_archive_creating_java(dst)
        builder_module.normalize_java_home_layout = lambda java_home: (java_home, False)

        assert ServerBuilder._download_graalvm_from_oracle(builder, 21) is True
    finally:
        builder_module.oracle_platform_triplet = original_platform
        builder_module.extract_archive = original_extract
        builder_module.normalize_java_home_layout = original_normalize

    assert download_calls == [
        (
            "https://download.oracle.com/otn/utilities_drivers/oracle-labs/graalvm21.tar.gz",
            {},
            None,
        )
    ]
    assert not (builder.workdirs.java_bins / "oracle-graalvm-21.tar.gz").exists()


def test_detect_command_probe_ready_accepts_player_count_line():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        "There are 0 of a max of 20 players online:",
    )

    assert ready is True
    assert source == "cmd_probe_list_response"


def test_extract_full_pack_version_payload_if_needed_moves_first_version_payload(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"client_temp": tmp_path / "client_temp"})()
    builder.workdirs.client_temp.mkdir(parents=True)
    builder.manifest = type(
        "Manifest",
        (),
        {"raw": {"full_pack": {"version_name": "1.20.1-forge-47.2.0"}}},
    )()

    version_dir = builder.workdirs.client_temp / ".minecraft" / "versions" / "1.20.1-forge-47.2.0"
    (version_dir / "mods").mkdir(parents=True)
    (version_dir / "config").mkdir(parents=True)
    (version_dir / "mods" / "a.jar").write_text("mod", encoding="utf-8")
    (version_dir / "config" / "settings.toml").write_text("cfg", encoding="utf-8")
    (version_dir / "1.20.1-forge-47.2.0.jar").write_text("client", encoding="utf-8")
    (version_dir / "1.20.1-forge-47.2.0.json").write_text("{}", encoding="utf-8")

    ServerBuilder._extract_full_pack_version_payload_if_needed(builder)

    assert (builder.workdirs.client_temp / "mods" / "a.jar").exists()
    assert (builder.workdirs.client_temp / "config" / "settings.toml").exists()
    assert not (builder.workdirs.client_temp / "1.20.1-forge-47.2.0.jar").exists()
    assert not (builder.workdirs.client_temp / "1.20.1-forge-47.2.0.json").exists()
    assert any(op.startswith("full_pack_extract:1.20.1-forge-47.2.0:copied=") for op in builder.operations)


def test_detect_command_probe_ready_ignores_case():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        "THERE ARE 0 OF A MAX OF 20 PLAYERS ONLINE:",
    )

    assert ready is True
    assert source == "cmd_probe_list_response"


def test_detect_command_probe_ready_rejects_unrelated_output():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        'Done (12.345s)! For help, type "help"',
    )

    assert ready is False
    assert source == ""


def test_detect_log_ready_signal_accepts_standard_done_line():
    ready, source = ServerBuilder._detect_log_ready_signal(
        None,
        '[23Mar2026 21:11:58] [Server thread/INFO] [minecraft/DedicatedServer]: Done (12.345s)! For help, type "help"',
    )

    assert ready is True
    assert source == "log_done"


def test_detect_log_ready_signal_rejects_plain_done_word_inside_error_log():
    ready, source = ServerBuilder._detect_log_ready_signal(
        None,
        "\n".join(
            [
                "[main/ERROR] Failed to create mod instance",
                "[worker/INFO] task done loading broken dependency metadata",
                (
                    "java.lang.RuntimeException: Attempted to load class "
                    "net/minecraft/client/gui/screens/Screen for invalid dist "
                    "DEDICATED_SERVER"
                ),
            ]
        ),
    )

    assert ready is False
    assert source == ""


def test_cf_post_json_wraps_request_error():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        curseforge_api_key="token",
        proxy=SimpleNamespace(to_requests_proxies=lambda: None, trust_env=True),
    )

    import mc_auto_server_builder.builder as builder_module

    original_session = builder_module.requests.Session
    try:
        class _RaiseSession:
            def __init__(self):
                self.proxies = {}
                self.trust_env = True

            def post(self, *_args, **_kwargs):
                raise builder_module.requests.ConnectionError("boom")

            def close(self):
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        builder_module.requests.Session = _RaiseSession
        with pytest.raises(ExternalRequestError, match="CurseForge POST 请求失败"):
            ServerBuilder._cf_post_json(builder, "/v1/mods/files", payload={})
    finally:
        builder_module.requests.Session = original_session


def test_cf_post_json_wraps_invalid_json_response():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = SimpleNamespace(
        curseforge_api_key="token",
        proxy=SimpleNamespace(to_requests_proxies=lambda: None, trust_env=True),
    )

    class _FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("bad json")

    import mc_auto_server_builder.builder as builder_module

    original_session = builder_module.requests.Session
    try:
        class _Session:
            def __init__(self):
                self.proxies = {}
                self.trust_env = True

            def post(self, *_args, **_kwargs):
                return _FakeResponse()

            def close(self):
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        builder_module.requests.Session = _Session
        with pytest.raises(ExternalDataError, match="不是合法 JSON"):
            ServerBuilder._cf_post_json(builder, "/v1/mods/files", payload={})
    finally:
        builder_module.requests.Session = original_session


def test_cf_fetch_files_batch_normalizes_payload_and_marks_unresolved():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder._cf_post_json = lambda *_args, **_kwargs: {
        "data": [
            {"id": 11, "modId": 1, "fileName": "one.jar", "downloadUrl": None, "extra": {"fingerprint": 1}},
            {"id": "bad", "modId": 2, "fileName": "broken.jar"},
        ]
    }

    resolution = ServerBuilder._cf_fetch_files_batch(builder, [(1, 11), (2, 22)], retry=0)

    assert resolution.unresolved == [(2, 22)]
    assert resolution.resolved[(1, 11)]["fileName"] == "one.jar"
    assert resolution.resolved[(1, 11)]["downloadUrl"] is None
    assert resolution.resolved[(1, 11)]["extra"] == {"fingerprint": 1}


def test_normalize_curseforge_file_payload_rejects_empty_or_non_mapping_payloads():
    assert _normalize_curseforge_file_payload(None) is None
    assert _normalize_curseforge_file_payload([]) is None
    assert _normalize_curseforge_file_payload({}) is None


def test_ensure_curseforge_manifest_mods_uses_fallback_result_when_batch_unresolved(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = SimpleNamespace(raw={"files": [{"projectID": 101, "fileID": 202}]})
    builder.config = SimpleNamespace(
        curseforge_api_key="token",
        download=SimpleNamespace(
            curseforge_manifest_batch_size=50,
            curseforge_manifest_batch_retry=0,
            manifest_resolve_parallel_enabled=True,
            manifest_resolve_max_workers=4,
        ),
    )
    builder.operations = []
    builder.remote_failure_events = []
    builder.downloader = SimpleNamespace(download_files=lambda tasks: (tasks, []))
    builder._classify_manifest_file_type = lambda **_kwargs: ("mods", True, "allowed")
    builder._record_manifest_type_decision = lambda **_kwargs: None
    builder._extract_curseforge_type_hints = lambda _data: []
    builder._build_curseforge_edge_download_url = lambda _data: None
    builder._manifest_target_path = lambda **kwargs: tmp_path / str(kwargs["file_name"])
    builder._cf_fetch_files_batch = lambda pairs, retry=0: SimpleNamespace(resolved={}, unresolved=list(pairs))

    def _cf_get_json(path: str):
        assert path == "/v1/mods/101/files/202"
        return {"data": {"id": 202, "modId": 101, "fileName": "fallback.jar", "downloadUrl": "https://example.invalid/fallback.jar"}}

    builder._cf_get_json = _cf_get_json

    ServerBuilder._ensure_curseforge_manifest_mods(builder)

    assert any(op.startswith("curseforge_manifest_fill:") and "fallback_hit=1" in op for op in builder.operations)
    assert not any(op == "curseforge_mod_meta_missing:101:202" for op in builder.operations)
    assert builder.remote_failure_events == []


def test_build_download_failure_detail_uses_structured_download_failure_fields(tmp_path):
    item = DownloadFailure(
        task=DownloadTask(out=tmp_path / "a.jar", urls=["https://example.invalid/a.jar"], stage="install.download.modrinth"),
        error="DownloadError:下载任务失败: a.jar",
        category="hash_mismatch",
        stage="install.download.modrinth",
        exc_type="DownloadError",
        message="hash_mismatch:a.jar",
    )

    detail = _build_download_failure_detail(item)

    assert detail == RemoteFailureDetail(
        stage="install.download.modrinth",
        category="hash_mismatch",
        exc_type="DownloadError",
        message="hash_mismatch:a.jar",
    )


def test_ensure_curseforge_manifest_mods_records_structured_failures_for_batch_fallback_and_no_url(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = SimpleNamespace(raw={"files": [{"projectID": 101, "fileID": 202}, {"projectID": 102, "fileID": 203}]})
    builder.config = SimpleNamespace(
        curseforge_api_key="token",
        download=SimpleNamespace(
            curseforge_manifest_batch_size=50,
            curseforge_manifest_batch_retry=0,
            manifest_resolve_parallel_enabled=False,
            manifest_resolve_max_workers=1,
        ),
    )
    builder.operations = []
    builder.remote_failure_events = []
    builder.downloader = SimpleNamespace(download_files=lambda tasks: ([], []))
    builder._classify_manifest_file_type = lambda **_kwargs: ("mod", True, "allowed")
    builder._record_manifest_type_decision = lambda **_kwargs: None
    builder._extract_curseforge_type_hints = lambda _data: []
    builder._build_curseforge_edge_download_url = lambda _data: None
    builder._manifest_target_path = lambda **kwargs: tmp_path / str(kwargs["file_name"])
    builder._cf_post_json = lambda *_args, **_kwargs: (_ for _ in ()).throw(ExternalRequestError("offline"))

    def _cf_get_json(path: str):
        if path.endswith("/101/files/202"):
            raise ExternalResponseError("missing")
        return {"data": {"id": 203, "modId": 102, "fileName": "missing-url.jar", "downloadUrl": None}}

    builder._cf_get_json = _cf_get_json

    ServerBuilder._ensure_curseforge_manifest_mods(builder)

    assert any(op.startswith("curseforge_manifest_batch_failed:") for op in builder.operations)
    assert any(op == "curseforge_mod_meta_missing:101:202" for op in builder.operations)
    assert any(op == "curseforge_mod_no_url:102:203" for op in builder.operations)
    assert any(
        event["operation"] == "curseforge_manifest_batch_failed"
        and event["category"] == "request"
        for event in builder.remote_failure_events
    )
    assert any(
        event["operation"] == "curseforge_manifest_fallback_failed"
        and event["category"] == "response"
        for event in builder.remote_failure_events
    )
    assert any(
        event["operation"] == "curseforge_mod_meta_missing"
        and event["category"] == "fallback_miss"
        for event in builder.remote_failure_events
    )
    assert any(
        event["operation"] == "curseforge_mod_no_url"
        and event["category"] == "no_url"
        for event in builder.remote_failure_events
    )


def test_ensure_modrinth_manifest_mods_records_hash_mismatch_after_fallback_failure(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = SimpleNamespace(
        raw={
            "files": [
                {
                    "path": "mods/example.jar",
                    "downloads": ["https://primary.invalid/example.jar", "https://mirror.invalid/example.jar"],
                    "hashes": {"sha1": "deadbeef"},
                    "project_id": "proj",
                    "file_id": "ver",
                }
            ]
        }
    )
    builder.operations = []
    builder.remote_failure_events = []
    builder._classify_manifest_file_type = lambda **_kwargs: ("mod", True, "allowed")
    builder._record_manifest_type_decision = lambda **_kwargs: None
    builder._extract_modrinth_type_hints = lambda _item: []
    builder._manifest_target_path = lambda **kwargs: tmp_path / kwargs["file_name"]

    primary_failure = DownloadFailure(
        task=DownloadTask(
            out=tmp_path / "example.jar",
            urls=["https://primary.invalid/example.jar"],
            stage="install.download.modrinth",
            expected_hashes={"sha1": "deadbeef"},
        ),
        error="DownloadError:hash_mismatch:example.jar",
        category="hash_mismatch",
        stage="install.download.modrinth",
        exc_type="DownloadError",
        message="hash_mismatch:example.jar",
    )

    builder.downloader = SimpleNamespace(
        download_files=lambda tasks: ([], [primary_failure]),
        download_task=lambda _task: (_ for _ in ()).throw(DownloadError("hash_mismatch:example.jar")),
    )

    ServerBuilder._ensure_modrinth_manifest_mods(builder)

    assert any(op.startswith("modrinth_manifest_fill_failed:") for op in builder.operations)
    assert any(
        event["operation"] == "modrinth_manifest_fill_failed"
        and event["category"] == "fallback_miss"
        for event in builder.remote_failure_events
    )


def test_ensure_modrinth_manifest_mods_records_no_url_as_structured_failure(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = SimpleNamespace(
        raw={
            "files": [
                {
                    "path": "mods/no-url.jar",
                    "downloads": [],
                    "project_id": "proj",
                    "file_id": "ver",
                }
            ]
        }
    )
    builder.operations = []
    builder.remote_failure_events = []
    builder._classify_manifest_file_type = lambda **_kwargs: ("mod", True, "allowed")
    builder._record_manifest_type_decision = lambda **_kwargs: None
    builder._extract_modrinth_type_hints = lambda _item: []
    builder._manifest_target_path = lambda **kwargs: tmp_path / kwargs["file_name"]

    ServerBuilder._ensure_modrinth_manifest_mods(builder)

    assert "modrinth_manifest_fill_no_url:mods/no-url.jar" in builder.operations
    assert any(
        event["operation"] == "modrinth_manifest_fill_no_url"
        and event["category"] == "no_url"
        for event in builder.remote_failure_events
    )

def test_start_server_detects_first_crash_report_and_kills_process(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=30,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._log = lambda *_args, **_kwargs: None
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 123
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    terminate_calls: list[tuple[object, float]] = []
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_terminate = builder_module.terminate_process
    original_sleep = builder_module.time.sleep
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        state = {"calls": 0}

        def fake_tail(*_args, **_kwargs):
            state["calls"] += 1
            if state["calls"] == 2:
                crash_dir = server_dir / "crash-reports"
                crash_dir.mkdir(parents=True, exist_ok=True)
                (crash_dir / "crash-1.txt").write_text("boom", encoding="utf-8")
            return ""

        builder_module.read_tail_text = fake_tail
        builder_module.is_local_tcp_port_open = lambda **_kwargs: False

        def fake_terminate(target_proc, timeout_sec=8.0):
            terminate_calls.append((target_proc, timeout_sec))
            target_proc.returncode = -9

        builder_module.terminate_process = fake_terminate
        builder_module.time.sleep = lambda *_args, **_kwargs: None

        result = ServerBuilder.start_server(builder, timeout=30)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.terminate_process = original_terminate
        builder_module.time.sleep = original_sleep

    assert result["success"] is False
    assert result["crash_detected"] is True
    assert result["forced_termination"] is True
    assert "crash_report_created" in result["failure_signals"]
    assert any(item.startswith("crash_reports_first_seen:") for item in result["readiness_evidence"])
    assert result["crash_reports_snapshot"] == ["crash-1.txt"]
    assert result["crash_reports_new"] == ["crash-1.txt"]
    assert terminate_calls == [(proc, 8.0)]


def test_start_server_detects_new_empty_crash_reports_dir_and_kills_process(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=30,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._log = lambda *_args, **_kwargs: None
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 124
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    terminate_calls: list[tuple[object, float]] = []
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_terminate = builder_module.terminate_process
    original_sleep = builder_module.time.sleep
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        state = {"calls": 0}

        def fake_tail(*_args, **_kwargs):
            state["calls"] += 1
            if state["calls"] == 2:
                (server_dir / "crash-reports").mkdir(parents=True, exist_ok=True)
            return ""

        builder_module.read_tail_text = fake_tail
        builder_module.is_local_tcp_port_open = lambda **_kwargs: False

        def fake_terminate(target_proc, timeout_sec=8.0):
            terminate_calls.append((target_proc, timeout_sec))
            target_proc.returncode = -9

        builder_module.terminate_process = fake_terminate
        builder_module.time.sleep = lambda *_args, **_kwargs: None

        result = ServerBuilder.start_server(builder, timeout=30)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.terminate_process = original_terminate
        builder_module.time.sleep = original_sleep

    assert result["success"] is False
    assert result["crash_detected"] is True
    assert result["forced_termination"] is True
    assert "crash_reports_dir_created" in result["readiness_evidence"]
    assert terminate_calls == [(proc, 8.0)]


def test_start_server_waits_for_crash_report_after_crash_reports_dir_created(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    server_dir.mkdir(parents=True)
    latest_log = server_dir / "logs" / "latest.log"
    latest_log.parent.mkdir(parents=True, exist_ok=True)
    latest_log.write_text("", encoding="utf-8")

    builder.workdirs = type("Workdirs", (), {"server": server_dir})()
    builder.config = type(
        "Cfg",
        (),
        {
            "runtime": type(
                "Runtime",
                (),
                {
                    "startup_command_probe_enabled": False,
                    "startup_probe_interval_sec": 0.2,
                    "startup_soft_timeout": 0.5,
                    "startup_hard_timeout": 30,
                    "startup_command_probe_initial_delay_sec": 1.0,
                    "startup_command_probe_retry_sec": 1.0,
                    "keep_running": False,
                },
            )(),
            "server_port": 25565,
        },
    )()
    builder.operations = []
    logs: list[tuple[str, str, str]] = []
    builder._log = lambda tag, message, level="INFO": logs.append((tag, level, message))
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {}
    builder._detect_failure_signals = lambda _text: []
    builder._detect_log_ready_signal = lambda _text: (False, "")
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 789
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    state = {"calls": 0}
    terminate_calls: list[tuple[object, float]] = []
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float):
        sleep_calls.append(seconds)
        if seconds == 2.0:
            crash_dir = server_dir / "crash-reports"
            crash_dir.mkdir(parents=True, exist_ok=True)
            crash_file = crash_dir / "crash-2026-03-23_22.18.31-server.txt"
            crash_file.write_text("crash content", encoding="utf-8")

    def fake_read_tail_text(_path: Path, lines: int = 300):
        state["calls"] += 1
        if state["calls"] == 2:
            crash_dir = server_dir / "crash-reports"
            crash_dir.mkdir(parents=True, exist_ok=True)
        return ""

    def fake_terminate_process(target_proc, timeout_sec: float = 8.0):
        terminate_calls.append((target_proc, timeout_sec))
        target_proc.returncode = -15

    original_popen = builder_module.subprocess.Popen
    original_read_tail_text = builder_module.read_tail_text
    original_terminate_process = builder_module.terminate_process
    original_is_local_tcp_port_open = builder_module.is_local_tcp_port_open
    original_sleep = builder_module.time.sleep
    builder_module.subprocess.Popen = lambda *args, **kwargs: proc
    builder_module.read_tail_text = fake_read_tail_text
    builder_module.terminate_process = fake_terminate_process
    builder_module.is_local_tcp_port_open = lambda *args, **kwargs: False
    builder_module.time.sleep = fake_sleep
    try:
        result = ServerBuilder.start_server(builder, timeout=30)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.read_tail_text = original_read_tail_text
        builder_module.terminate_process = original_terminate_process
        builder_module.is_local_tcp_port_open = original_is_local_tcp_port_open
        builder_module.time.sleep = original_sleep

    assert result["crash_detected"] is True
    assert any(item.startswith("crash_reports_first_seen:") for item in result["readiness_evidence"])
    assert 2.0 in sleep_calls
    assert any(tag == "install.crash" and "等待 2 秒" in message for tag, _level, message in logs)
    assert any(tag == "install.crash" and "准备进入日志提取与 AI 分析" in message for tag, _level, message in logs)
    assert terminate_calls == [(proc, 8.0)]


def test_start_server_detects_increased_crash_reports(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    crash_dir = server_dir / "crash-reports"
    crash_dir.mkdir(parents=True)
    (crash_dir / "crash-old.txt").write_text("old", encoding="utf-8")
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=30,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._log = lambda *_args, **_kwargs: None
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 456
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_terminate = builder_module.terminate_process
    original_sleep = builder_module.time.sleep
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        state = {"calls": 0}

        def fake_tail(*_args, **_kwargs):
            state["calls"] += 1
            if state["calls"] == 2:
                (crash_dir / "crash-new.txt").write_text("new", encoding="utf-8")
            return ""

        builder_module.read_tail_text = fake_tail
        builder_module.is_local_tcp_port_open = lambda **_kwargs: False
        builder_module.terminate_process = lambda target_proc, timeout_sec=8.0: setattr(target_proc, "returncode", -9)
        builder_module.time.sleep = lambda *_args, **_kwargs: None

        result = ServerBuilder.start_server(builder, timeout=30)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.terminate_process = original_terminate
        builder_module.time.sleep = original_sleep

    assert result["success"] is False
    assert result["crash_detected"] is True
    assert any(item.startswith("crash_reports_increased:") for item in result["readiness_evidence"])
    assert result["crash_reports_snapshot"] == ["crash-new.txt", "crash-old.txt"]
    assert result["crash_reports_new"] == ["crash-new.txt"]


def test_build_ai_context_exposes_last_rollback_crash_report_comparison():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = None
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.operations = ["remove_mod_by_name:a.jar", "action_rollback:remove_mods:attempt_1_action_1"]
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.last_rollback_remove_mods = {
        "triggered": True,
        "snapshot_tag": "attempt_1_action_1",
        "crash_reports_after_validation": ["crash-old.txt"],
        "validation_crash_excerpt": "old crash",
        "crash_reports_changed_since_last_context": False,
    }
    builder._coerce_bisect_session = lambda: SimpleNamespace(
        active=False,
        next_allowed_requests=[],
        fallback_targets=[],
        suspects_invalidated=False,
        phase="initial",
        stagnant_rounds=0,
        last_preflight_block_reason="",
        last_preflight_block_details=[],
        success_ready=False,
        success_guard_reason="",
        success_guard_history=[],
        consecutive_same_issue_on_success=0,
    )
    builder._build_recognition_summary = lambda: {}
    builder.get_system_memory = lambda: 16.0
    builder.list_mods = lambda: ["a.jar", "b.jar"]
    builder.list_current_installed_client_mods = lambda: []

    context = ServerBuilder._build_ai_context(
        builder,
        {"stdout_tail": "", "stderr_tail": "", "crash_reports_snapshot": ["crash-new.txt"]},
        {"key_exception": "RuntimeException", "refined_log": "", "crash_mod_issue": ""},
    )

    assert context["last_crash_reports"] == ["crash-old.txt"]
    assert context["current_crash_reports"] == ["crash-new.txt"]
    assert context["crash_report_delta"] == ["crash-new.txt", "crash-old.txt"]
    assert context["crash_reports_changed_since_last_rollback_remove"] is True
    assert builder.last_rollback_remove_mods["crash_reports_changed_since_last_context"] is True


def test_preflight_blocks_restore_when_crash_reports_unchanged():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.remove_validation_state = {
        "continue_allowed": True,
        "rollback_snapshot_tag": "attempt_1_action_1",
        "post_remove_active_mods": ["good.jar"],
        "problem_changed": False,
        "continued": False,
    }

    preflight = ServerBuilder._assess_action_preflight(builder, {"type": "continue_after_restore_mods"})

    assert preflight.allowed is False
    assert preflight.reason == "remove_validation_problem_not_changed"


def test_execute_continue_after_restore_mods_rolls_back_snapshot():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.remove_validation_state = {
        "continue_allowed": True,
        "rollback_snapshot_tag": "attempt_1_action_1",
        "post_remove_active_mods": ["good.jar"],
        "removed_targets": ["bad.jar"],
        "problem_changed": True,
        "continued": False,
    }
    builder.rollback_mods = lambda tag: builder.__dict__.setdefault("rollback_calls", []).append(tag)
    builder._set_active_mods = lambda active_mods, snapshot_tag, reason: builder.__dict__.setdefault("set_active_calls", []).append(
        (list(active_mods), snapshot_tag, reason)
    ) or list(active_mods)
    builder.operations = []
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.extra_jvm_flags = []
    builder.current_java_version = 21
    builder.current_java_bin = None

    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        1,
        {"type": "continue_after_restore_mods"},
        ActionPreflight(action_type="continue_after_restore_mods", risk="low", allowed=True, reason="remove_validation_continue_allowed"),
        "attempt_2_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert execution["restored_snapshot_tag"] == "attempt_1_action_1"
    assert execution["restored_active_mods"] == ["good.jar"]
    assert not hasattr(builder, "rollback_calls")
    assert builder.set_active_calls == [(["good.jar"], "attempt_1_action_1", "continue_after_restore_mods")]
    assert "continue_after_restore_mods:attempt_1_action_1" in builder.operations
    assert builder.remove_validation_state["continued"] is True


def test_remove_validation_state_payload_normalizes_dynamic_mapping():
    payload = RemoveValidationStatePayload.from_mapping(
        {
            "continue_allowed": 1,
            "rollback_snapshot_tag": " attempt_1_action_1 ",
            "post_remove_active_mods": ["good.jar", "", None],
            "removed_targets": ["bad.jar", 123],
            "failure_signals": ["missing dependency", " "],
        }
    )

    assert payload.continue_allowed is True
    assert payload.rollback_snapshot_tag == "attempt_1_action_1"
    assert payload.post_remove_active_mods == ["good.jar"]
    assert payload.removed_targets == ["bad.jar", "123"]
    assert payload.failure_signals == ["missing dependency"]


def test_start_server_terminates_hanging_process_without_success(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=1,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 789
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    terminate_calls: list[tuple[object, float]] = []
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_terminate = builder_module.terminate_process
    original_monotonic = builder_module.time.monotonic
    original_sleep = builder_module.time.sleep
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        builder_module.read_tail_text = lambda *_args, **_kwargs: ""
        builder_module.is_local_tcp_port_open = lambda **_kwargs: False

        def fake_terminate(target_proc, timeout_sec=8.0):
            terminate_calls.append((target_proc, timeout_sec))
            target_proc.returncode = -15

        builder_module.terminate_process = fake_terminate
        ticks = iter([0.0, 0.4, 0.8, 1.2])
        builder_module.time.monotonic = lambda: next(ticks)
        builder_module.time.sleep = lambda *_args, **_kwargs: None

        result = ServerBuilder.start_server(builder, timeout=1)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.terminate_process = original_terminate
        builder_module.time.monotonic = original_monotonic
        builder_module.time.sleep = original_sleep

    assert result["success"] is False
    assert result["forced_termination"] is True
    assert "hard_timeout_reached" in result["readiness_evidence"]
    assert "forced_termination" in result["readiness_evidence"]
    assert terminate_calls == [(proc, 8.0)]


def test_start_server_requires_log_or_command_probe_success(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=30,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            return None

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 321
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    graceful_calls: list[tuple[object, float, str]] = []
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_graceful = builder_module.graceful_stop_process
    original_sleep = builder_module.time.sleep
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        builder_module.read_tail_text = lambda *_args, **_kwargs: 'Done (12.345s)! For help, type "help"'
        builder_module.is_local_tcp_port_open = lambda **_kwargs: True

        def fake_graceful(target_proc, timeout_sec=20.0, stop_command="stop"):
            graceful_calls.append((target_proc, timeout_sec, stop_command))
            target_proc.returncode = 0

        builder_module.graceful_stop_process = fake_graceful
        builder_module.time.sleep = lambda *_args, **_kwargs: None

        result = ServerBuilder.start_server(builder, timeout=30)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.graceful_stop_process = original_graceful
        builder_module.time.sleep = original_sleep

    assert result["success"] is True
    assert result["crash_detected"] is False
    assert result["forced_termination"] is False
    assert result["success_source"] == "log_done"


def test_terminate_process_kills_process_tree(monkeypatch):
    from mc_auto_server_builder import util as util_module

    class FakePsProc:
        def __init__(self, pid, children=None, wait_outcomes=None):
            self.pid = pid
            self._children = children or []
            self._wait_outcomes = list(wait_outcomes or [])
            self.terminated = 0
            self.killed = 0

        def children(self, recursive=True):
            return list(self._children)

        def terminate(self):
            self.terminated += 1

        def kill(self):
            self.killed += 1

        def wait(self, timeout=None):
            if self._wait_outcomes:
                outcome = self._wait_outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
            return 0

    class FakePopen:
        pid = 100

        def poll(self):
            return None

    child = FakePsProc(101, wait_outcomes=[psutil.TimeoutExpired(1, 0), 0])
    root = FakePsProc(100, children=[child], wait_outcomes=[0])
    monkeypatch.setattr(util_module.psutil, "Process", lambda pid: root)

    util_module.terminate_process(FakePopen(), timeout_sec=1.0)

    assert child.terminated == 1
    assert root.terminated == 1
    assert child.killed == 1
    assert root.killed == 0


def test_start_server_does_not_close_blocking_pipes(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    server_dir = tmp_path / "server"
    (server_dir / "logs").mkdir(parents=True)
    builder.workdirs = SimpleNamespace(server=server_dir)
    builder.config = SimpleNamespace(
        runtime=SimpleNamespace(
            startup_command_probe_enabled=False,
            startup_probe_interval_sec=0.2,
            startup_soft_timeout=8,
            startup_hard_timeout=30,
            startup_command_probe_initial_delay_sec=1.0,
            startup_command_probe_retry_sec=1.0,
            keep_running=False,
        ),
        server_port=25565,
    )
    builder.operations = []
    builder._start_script_path = lambda: server_dir / "start.sh"
    builder._write_start_script = lambda: (server_dir / "start.sh").write_text("#!/bin/sh", encoding="utf-8")
    builder._collect_process_resource_snapshot = lambda _proc: {"rss_mb": 0.0, "cpu_percent": 0.0, "process_count": 1}
    builder._detect_failure_signals = ServerBuilder._detect_failure_signals.__get__(builder, ServerBuilder)
    builder._detect_log_ready_signal = ServerBuilder._detect_log_ready_signal.__get__(builder, ServerBuilder)
    builder._detect_command_probe_ready = ServerBuilder._detect_command_probe_ready.__get__(builder, ServerBuilder)
    builder._snapshot_crash_reports = ServerBuilder._snapshot_crash_reports.__get__(builder, ServerBuilder)

    import mc_auto_server_builder.builder as builder_module

    class FakePipe:
        def close(self):
            raise AssertionError("close should not be called")

    class FakeThread:
        def __init__(self, target=None, args=(), daemon=None):
            self.target = target
            self.args = args
            self.daemon = daemon
            self.join_calls = []

        def start(self):
            return None

        def join(self, timeout=None):
            self.join_calls.append(timeout)

    class FakeProc:
        def __init__(self):
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.stdin = None
            self.pid = 321
            self.returncode = None

        def poll(self):
            return self.returncode

    proc = FakeProc()
    terminate_calls: list[tuple[object, float]] = []
    thread_instances: list[FakeThread] = []
    original_popen = builder_module.subprocess.Popen
    original_reader = builder_module.threaded_pipe_reader
    original_tail = builder_module.read_tail_text
    original_port = builder_module.is_local_tcp_port_open
    original_terminate = builder_module.terminate_process
    original_sleep = builder_module.time.sleep
    original_thread = builder_module.threading.Thread
    try:
        builder_module.subprocess.Popen = lambda *args, **kwargs: proc
        builder_module.threaded_pipe_reader = lambda pipe, out: None
        builder_module.read_tail_text = lambda *_args, **_kwargs: ""
        builder_module.is_local_tcp_port_open = lambda **_kwargs: False

        def fake_terminate(target_proc, timeout_sec=8.0):
            terminate_calls.append((target_proc, timeout_sec))
            target_proc.returncode = -9

        def fake_thread(*args, **kwargs):
            inst = FakeThread(*args, **kwargs)
            thread_instances.append(inst)
            return inst

        builder_module.terminate_process = fake_terminate
        builder_module.time.sleep = lambda *_args, **_kwargs: None
        builder_module.threading.Thread = fake_thread

        result = ServerBuilder.start_server(builder, timeout=1)
    finally:
        builder_module.subprocess.Popen = original_popen
        builder_module.threaded_pipe_reader = original_reader
        builder_module.read_tail_text = original_tail
        builder_module.is_local_tcp_port_open = original_port
        builder_module.terminate_process = original_terminate
        builder_module.time.sleep = original_sleep
        builder_module.threading.Thread = original_thread

    assert result["success"] is False
    assert result["forced_termination"] is True
    assert terminate_calls == [(proc, 8.0)]
    assert len(thread_instances) == 2
    assert all(item.join_calls == [1.0] for item in thread_instances)


def test_detect_failure_signals_matches_common_runtime_errors():
    builder = ServerBuilder.__new__(ServerBuilder)

    result = ServerBuilder._detect_failure_signals(
        builder,
        "UnsupportedClassVersionError\nAddress already in use\nOutOfMemoryError\nwatchdog",
    )

    assert "java_version_mismatch" in result
    assert "port_in_use" in result
    assert "memory_oom" in result
    assert "watchdog_or_deadlock" in result


def test_select_java_version_prefers_top_recognition_plan():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(
        pack_name="demo",
        mc_version="1.20.1",
        loader="forge",
        start_mode="jar",
        loader_candidates=[DetectionCandidate(value="neoforge", confidence=0.95)],
        mc_version_candidates=[DetectionCandidate(value="1.21.1", confidence=0.95)],
        start_mode_candidates=[DetectionCandidate(value="args_file", confidence=0.95)],
    )
    builder._build_recognition_candidates = ServerBuilder._build_recognition_candidates.__get__(builder, ServerBuilder)

    selected = ServerBuilder._select_java_version_for_current_manifest(builder)

    assert selected == 21


def test_build_recognition_summary_exposes_runtime_feedback_stats():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(
        pack_name="demo",
        mc_version="1.20.1",
        loader="forge",
        loader_version="1.20.1-47.2.0",
        build="47.2.0",
        start_mode="args_file",
    )
    builder.recognition_attempts = [
        {"reason": "runtime_feedback_fallback", "loader": "fabric"},
        {"reason": "manual_switch", "loader": "forge"},
    ]
    builder._serialize_detection_candidates = ServerBuilder._serialize_detection_candidates.__get__(builder, ServerBuilder)

    summary = ServerBuilder._build_recognition_summary(builder)

    assert summary["recognition_strategy_used"] == "unknown"
    assert summary["recognition_fallback_count"] == 2
    assert summary["recognition_switched"] is True
    assert summary["recognition_finalized_after_runtime_feedback"] is True


def test_copy_client_files_with_blacklist_keeps_server_resourcepack_subset(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"client_temp": tmp_path / "client", "server": tmp_path / "server"})()
    builder.workdirs.client_temp.mkdir(parents=True)
    builder.workdirs.server.mkdir(parents=True)
    builder._extract_server_resourcepacks = ServerBuilder._extract_server_resourcepacks.__get__(builder, ServerBuilder)

    resourcepacks = builder.workdirs.client_temp / "resourcepacks"
    resourcepacks.mkdir()
    (resourcepacks / "keep.zip").write_text("zip", encoding="utf-8")
    (resourcepacks / "skip.txt").write_text("txt", encoding="utf-8")
    kept_dir = resourcepacks / "server-pack"
    kept_dir.mkdir()
    (kept_dir / "pack.mcmeta").write_text("{}", encoding="utf-8")

    copied, skipped = ServerBuilder._copy_client_files_with_blacklist(builder, {"resourcepacks"})

    assert copied == 2
    assert skipped == 0
    assert (builder.workdirs.server / "resourcepacks" / "keep.zip").exists()
    assert (builder.workdirs.server / "resourcepacks" / "server-pack" / "pack.mcmeta").exists()
    assert not (builder.workdirs.server / "resourcepacks" / "skip.txt").exists()


def test_normalize_client_relative_path_accepts_server_override_aliases():
    from mc_auto_server_builder.util import normalize_client_relative_path

    assert normalize_client_relative_path("server-overrides/config/a.toml") == "config/a.toml"
    assert normalize_client_relative_path("server_overrides/mods/a.jar") == "mods/a.jar"


def test_normalize_ai_result_injects_manual_fix_action_when_only_manual_guidance_exists():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    result = service._normalize_ai_result(
        {
            "final_output": {
                "primary_issue": "config_error",
                "confidence": 0.81,
                "reason": "配置文件语法错误导致启动失败",
                "user_summary": "服务端因配置错误崩溃，需要人工修正配置。",
                "suggested_manual_steps": ["检查 mods 对应的配置文件", "回滚最近修改的配置项"],
                "evidence": ["Found invalid config entry", "Failed to load config file"],
                "actions": [],
            }
        },
    )

    assert result.primary_issue == "config_error"
    assert result.user_summary == "服务端因配置错误崩溃，需要人工修正配置。"
    assert result.actions[0].type == "report_manual_fix"
    assert result.actions[0].manual_steps == ["检查 mods 对应的配置文件", "回滚最近修改的配置项"]
    assert result.actions[0].evidence == ["Found invalid config entry", "Failed to load config file"]


def test_apply_actions_report_manual_fix_stops_and_records_report():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    builder.ai_service = BuilderAIService(builder)
    builder._normalize_text_list = ServerBuilder._normalize_text_list.__get__(builder, ServerBuilder)
    builder.operations = []
    builder.stop_reason = ""
    builder.last_ai_manual_report = {}
    builder.last_ai_result = AIResult(
        primary_issue="other",
        confidence=0.7,
        reason="需要人工处理",
        user_summary="这是一个需要人工介入的问题。",
        suggested_manual_steps=["查看崩溃日志", "检查 mod 版本兼容性"],
        evidence=["Mixin apply failed", "Caused by: java.lang.NoSuchMethodError"],
    )

    should_stop = ServerBuilder._apply_actions(
        builder,
        [
            {
                "type": "report_manual_fix",
                "final_reason": "需要人工修复 mod 冲突",
                "manual_steps": ["禁用最近新增的 mod", "升级冲突 mod 到兼容版本"],
                "evidence": ["Duplicate mod id detected"],
            }
        ],
    )

    assert should_stop is True
    assert builder.stop_reason == "需要人工修复 mod 冲突"
    assert builder.operations[-1] == "report_manual_fix:需要人工修复 mod 冲突"
    assert builder.last_ai_manual_report == {
        "user_summary": "这是一个需要人工介入的问题。",
        "suggested_manual_steps": ["禁用最近新增的 mod", "升级冲突 mod 到兼容版本"],
        "evidence": ["Duplicate mod id detected"],
    }


def test_analyze_with_ai_uses_composed_ai_service_when_disabled():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.operations = []
    builder.last_ai_payload = {"stale": True}
    builder.last_ai_result = None
    builder.last_ai_manual_report = {"stale": True}
    builder.attempts_used = 0
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    builder.ai_service = BuilderAIService(builder)

    result = ServerBuilder.analyze_with_ai(builder, {})

    assert result["reason"] == "AI未启用，返回保守策略"
    assert result["actions"][0]["type"] == "stop_and_report"
    assert builder.last_ai_payload == {}
    assert builder.last_ai_result is not None


def test_normalize_ai_result_accepts_bisect_mods_action():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    result = service._normalize_ai_result(
        {
            "final_output": {
                "primary_issue": "mod_conflict",
                "confidence": 0.72,
                "reason": "需要二分定位问题 mod",
                "actions": [
                    {
                        "type": "bisect_mods",
                        "bisect_mode": "initial",
                        "targets": ["a.jar", "b.jar", "lib.jar"],
                        "bisect_reason": "申请系统执行稳定二分",
                        "max_rounds": 1,
                    }
                ],
            }
        },
    )

    assert result.actions[0].type == "bisect_mods"
    assert result.actions[0].bisect_mode == "initial"
    assert result.actions[0].bisect_reason == "申请系统执行稳定二分"


def test_normalize_ai_result_accepts_move_bisect_mods_action():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    result = service._normalize_ai_result(
        {
            "final_output": {
                "primary_issue": "missing_dependency",
                "confidence": 0.72,
                "reason": "需要迁移依赖",
                "actions": [
                    {
                        "type": "move_bisect_mods",
                        "targets": ["lib.jar"],
                        "reason": "迁移依赖",
                    }
                ],
            }
        }
    )

    assert result.actions[0].type == "move_bisect_mods"
    assert result.actions[0].targets == ["lib.jar"]


def test_build_prompt_uses_compact_rule_sections_for_bisect_state():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    prompt = service.build_prompt(
        {
            "bisect_active": True,
            "bisect_next_allowed_requests": ["initial"],
            "bisect_fallback_targets": ["a.jar", "b.jar"],
            "bisect_suspects_invalidated": True,
        }
    )

    assert "硬规则：1." in prompt
    assert "二分状态机：1." in prompt
    assert "动作优先级：1." in prompt
    assert "suspects_invalidated=true 且 next_allowed_requests 包含 initial" in prompt
    assert "新的 fallback initial phase" in prompt
    assert "仅当 bisect_state.active=true 且 next_allowed_requests 为空时" in prompt
    assert "禁止再次输出任何 bisect_mods" in prompt
    assert "move_bisect_mods" in prompt
    assert "targets 表示要从另一组临时迁移到当前测试组的少量 mod" in prompt
    assert "rollback_on_failure=true" in prompt


def test_normalize_ai_result_accepts_remove_mods_rollback_flag():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    result = service._normalize_ai_result(
        {
            "final_output": {
                "primary_issue": "mod_conflict",
                "confidence": 0.88,
                "reason": "高置信删除但需要失败回滚",
                "actions": [
                    {
                        "type": "remove_mods",
                        "targets": ["bad.jar"],
                        "rollback_on_failure": True,
                    }
                ],
            }
        },
    )

    assert result.actions[0].type == "remove_mods"
    assert result.actions[0].targets == ["bad.jar"]
    assert result.actions[0].rollback_on_failure is True


def test_execute_remove_mods_with_rollback_on_failure_restores_snapshot():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_dependency_cleanup_targets = lambda *_args, **_kwargs: ([], [], [])
    builder.ai_service = BuilderAIService(builder)
    builder.last_ai_result = AIResult(primary_issue="mod_conflict", confidence=0.9, reason="test")

    state = {"mods": ["bad.jar", "good.jar"], "snapshot": ["bad.jar", "good.jar"]}

    def list_mods():
        return list(state["mods"])

    def backup_mods(_tag: str):
        state["snapshot"] = list(state["mods"])

    def rollback_mods(_tag: str):
        state["mods"] = list(state["snapshot"])

    def remove_mods_by_name(names: list[str], source: str = "manual", reason: str = ""):
        state["mods"] = [m for m in state["mods"] if m not in names]

    def start_server(timeout: int = 300):
        return {"success": False, "reason": "missing dependency", "stdout": "", "stderr": "Mod loading failed"}

    builder.list_mods = list_mods
    builder.backup_mods = backup_mods
    builder.rollback_mods = rollback_mods
    builder.remove_mods_by_name = remove_mods_by_name
    builder.start_server = start_server

    preflight = ActionPreflight(action_type="remove_mods", risk="medium", allowed=True, reason="resolved_low_volume_mod_removal")
    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        1,
        {"type": "remove_mods", "targets": ["bad.jar"], "rollback_on_failure": True},
        preflight,
        snapshot_tag="attempt_1_action_1",
    )

    assert stop is False
    assert execution["status"] == "rolled_back"
    assert builder.remove_validation_state["continue_allowed"] is False


def test_execute_remove_mods_with_rollback_on_failure_records_changed_problem_context():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_dependency_cleanup_targets = lambda *_args, **_kwargs: ([], [], [])
    builder._extract_log_signal_lines = ServerBuilder._extract_log_signal_lines.__get__(builder, ServerBuilder)
    builder.ai_service = BuilderAIService(builder)
    builder.last_ai_result = AIResult(primary_issue="mod_conflict", confidence=0.9, reason="test")
    builder.last_rollback_remove_mods = {
        "crash_reports_after_validation": ["old-crash.txt"],
        "validation_crash_excerpt": "old crash",
    }

    state = {"mods": ["bad.jar", "good.jar"], "snapshot": ["bad.jar", "good.jar"]}

    def list_mods():
        return list(state["mods"])

    def backup_mods(_tag: str):
        state["snapshot"] = list(state["mods"])

    def rollback_mods(_tag: str):
        state["mods"] = list(state["snapshot"])

    def remove_mods_by_name(names: list[str], source: str = "manual", reason: str = ""):
        state["mods"] = [m for m in state["mods"] if m not in names]

    def start_server(timeout: int = 300):
        return {
            "success": False,
            "reason": "new dependency chain",
            "stdout": "",
            "stderr": "Different crash",
            "crash_reports_snapshot": ["new-crash.txt"],
            "failure_signals": ["missing dependency"],
            "readiness_evidence": [],
        }

    builder.list_mods = list_mods
    builder.backup_mods = backup_mods
    builder.rollback_mods = rollback_mods
    builder.remove_mods_by_name = remove_mods_by_name
    builder.start_server = start_server

    preflight = ActionPreflight(action_type="remove_mods", risk="medium", allowed=True, reason="resolved_low_volume_mod_removal")
    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        1,
        {"type": "remove_mods", "targets": ["bad.jar"], "rollback_on_failure": True},
        preflight,
        snapshot_tag="attempt_1_action_1",
    )

    assert stop is False
    assert execution["validation_problem_changed"] is True
    assert rollback is not None and rollback["performed"] is True
    assert builder.remove_validation_state["continue_allowed"] is True
    assert builder.remove_validation_state["problem_changed"] is True
    assert builder.remove_validation_state["rollback_snapshot_tag"] == "attempt_1_action_1"
    assert builder.remove_validation_state["post_remove_active_mods"] == ["good.jar"]
    assert builder.remove_validation_state["crash_report_delta"] == ["new-crash.txt", "old-crash.txt"]


def test_execute_remove_mods_normalizes_validation_payload_lists():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_dependency_cleanup_targets = lambda *_args, **_kwargs: ([], [], [])
    builder._extract_log_signal_lines = ServerBuilder._extract_log_signal_lines.__get__(builder, ServerBuilder)
    builder.ai_service = BuilderAIService(builder)
    builder.last_ai_result = AIResult(primary_issue="mod_conflict", confidence=0.9, reason="test")
    builder.last_rollback_remove_mods = {}

    state = {"mods": ["bad.jar", "good.jar"], "snapshot": ["bad.jar", "good.jar"]}

    builder.list_mods = lambda: list(state["mods"])
    builder.backup_mods = lambda _tag: state.__setitem__("snapshot", list(state["mods"]))
    builder.rollback_mods = lambda _tag: state.__setitem__("mods", list(state["snapshot"]))
    builder.remove_mods_by_name = lambda names, source="manual", reason="": state.__setitem__(
        "mods", [m for m in state["mods"] if m not in names]
    )
    builder.start_server = lambda timeout=300: {
        "success": False,
        "reason": "new dependency chain",
        "crash_reports_snapshot": ["new-crash.txt", "", None],
        "failure_signals": ["missing dependency", None],
        "readiness_evidence": ["", "partial init"],
    }

    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        1,
        {"type": "remove_mods", "targets": ["bad.jar"], "rollback_on_failure": True},
        ActionPreflight(action_type="remove_mods", risk="medium", allowed=True, reason="resolved_low_volume_mod_removal"),
        snapshot_tag="attempt_1_action_1",
    )

    assert stop is False
    assert execution["status"] == "rolled_back"
    assert rollback is not None and rollback["performed"] is True
    assert builder.remove_validation_state["validation_crash_reports"] == ["new-crash.txt"]
    assert builder.remove_validation_state["failure_signals"] == ["missing dependency"]
    assert builder.remove_validation_state["readiness_evidence"] == ["partial init"]


def test_execute_adjust_memory_uses_extracted_executor_flow():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.extra_jvm_flags = []
    builder.current_java_version = 21
    builder.current_java_bin = None
    calls: list[tuple[str, str]] = []
    builder._normalize_memory_plan = lambda xmx, xms: ("6G", "3G")
    builder.set_jvm_args = lambda xmx, xms, extra_flags=None: calls.append((xmx, xms))

    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        2,
        {"type": "adjust_memory", "xmx": "6144M", "xms": "3072M"},
        ActionPreflight(action_type="adjust_memory", risk="low", allowed=True, reason="memory_increase_allowed"),
        "attempt_1_action_2",
    )

    assert stop is False
    assert rollback is None
    assert calls == [("6G", "3G")]
    assert execution["status"] == "applied"
    assert execution["xmx"] == "6G"
    assert execution["xms"] == "3G"


def test_execute_change_java_uses_extracted_executor_flow():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.extra_jvm_flags = []
    builder.current_java_version = 21
    builder.current_java_bin = None
    switched: list[int] = []
    builder.switch_java_version = lambda version: switched.append(version)

    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        3,
        {"type": "change_java", "version": 17},
        ActionPreflight(action_type="change_java", risk="low", allowed=True, reason="java_version_switch_allowed"),
        "attempt_1_action_3",
    )

    assert stop is False
    assert rollback is None
    assert switched == [17]
    assert execution["status"] == "applied"
    assert execution["version"] == 17


def test_consume_remove_validation_followup_runs_special_stage_before_main_ai():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.remove_validation_state = {
        "continue_allowed": True,
        "continued": False,
        "rollback_snapshot_tag": "attempt_1_action_1",
        "post_remove_active_mods": ["good.jar"],
        "problem_changed": True,
    }
    builder.stop_reason = ""
    builder.operations = []
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder._append_attempt_trace = lambda *_args, **_kwargs: None
    builder._summarize_ai_context = lambda context: {"mods": context.get("mod_state", {}).get("current_installed_mods", [])}
    builder._build_ai_context = lambda start_res, log_info: {
        "mod_state": {"current_installed_mods": ["bad.jar", "good.jar"]},
        "raw_evidence": {"log_tail_preview": log_info.get("log_tail", "")},
    }
    calls: list[str] = []

    def analyze_remove_validation_with_ai(context: dict):
        calls.append(f"rv:{context.get('remove_validation_state', {}).get('post_remove_active_mods')}")
        return {
            "primary_issue": "mod_conflict",
            "confidence": 0.9,
            "actions": [{"type": "continue_after_restore_mods"}],
        }

    def apply_actions(actions: list[dict], attempt: int = 0):
        if actions and actions[0].get("type") == "continue_after_restore_mods":
            builder.remove_validation_state["continued"] = True
        return False

    def analyze_with_ai(context: dict):
        calls.append(f"main:{context.get('remove_validation_state', {}).get('continued')}")
        return {
            "primary_issue": "other",
            "confidence": 0.5,
            "actions": [],
        }

    builder.analyze_remove_validation_with_ai = analyze_remove_validation_with_ai
    builder._apply_actions = apply_actions
    builder.analyze_with_ai = analyze_with_ai

    result = ServerBuilder._consume_remove_validation_followup(
        builder,
        2,
        {"success": False},
        {"log_tail": "changed crash"},
    )

    assert result is False
    assert calls == ["rv:['good.jar']", "main:True"]


def test_consume_remove_validation_followup_skips_when_state_not_pending():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.remove_validation_state = {"continue_allowed": True, "continued": True}

    result = ServerBuilder._consume_remove_validation_followup(builder, 1, {"success": False}, {"log_tail": "x"})

    assert result is None


def test_select_java_version_for_manifest_uses_loader_and_version_bias():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(pack_name="pack", mc_version="1.21.1", loader="neoforge")

    version = ServerBuilder._select_java_version_for_current_manifest(builder)

    assert version == 21


def test_choose_latest_lts_java_version_returns_supported_lts():
    assert choose_latest_lts_java_version() == 21


def test_apply_modern_loader_start_mode_prefers_args_file(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.start_command_mode = "jar"
    builder.start_command_value = builder.server_jar_name
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(pack_name="Pack", mc_version="1.20.1", loader="forge", loader_version="1.20.1-47.2.0")
    builder._set_start_command = ServerBuilder._set_start_command.__get__(builder, ServerBuilder)
    (tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.20.1-47.2.0").mkdir(parents=True)
    (tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.20.1-47.2.0" / "unix_args.txt").write_text("args", encoding="utf-8")

    applied = ServerBuilder._apply_modern_loader_start_mode(builder)

    assert applied is True
    assert builder.start_command_mode == "argsfile"
    assert builder.start_command_value.endswith("unix_args.txt")


def test_apply_modern_loader_start_mode_prefers_manifest_matching_loader_and_version(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.start_command_mode = "jar"
    builder.start_command_value = builder.server_jar_name
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="Pack",
        mc_version="1.20.1",
        loader="forge",
        loader_version="1.20.1-47.2.0",
    )
    builder._set_start_command = ServerBuilder._set_start_command.__get__(builder, ServerBuilder)
    forge_dir = tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.20.1-47.2.0"
    neo_dir = tmp_path / "libraries" / "net" / "neoforged" / "neoforge" / "21.0.10"
    forge_dir.mkdir(parents=True)
    neo_dir.mkdir(parents=True)
    (forge_dir / "unix_args.txt").write_text("args", encoding="utf-8")
    (neo_dir / "unix_args.txt").write_text("args", encoding="utf-8")

    applied = ServerBuilder._apply_modern_loader_start_mode(builder)

    assert applied is True
    assert builder.start_command_value == "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt"


def test_apply_modern_loader_start_mode_prefers_neoforge_candidate_when_manifest_is_neoforge(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.start_command_mode = "jar"
    builder.start_command_value = builder.server_jar_name
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="Pack",
        mc_version="1.21.1",
        loader="neoforge",
        loader_version="21.1.1-beta",
    )
    builder._set_start_command = ServerBuilder._set_start_command.__get__(builder, ServerBuilder)
    forge_dir = tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.21.1-52.0.1"
    neo_dir = tmp_path / "libraries" / "net" / "neoforged" / "neoforge" / "21.1.1-beta"
    forge_dir.mkdir(parents=True)
    neo_dir.mkdir(parents=True)
    (forge_dir / "unix_args.txt").write_text("args", encoding="utf-8")
    (neo_dir / "unix_args.txt").write_text("args", encoding="utf-8")

    applied = ServerBuilder._apply_modern_loader_start_mode(builder)

    assert applied is True
    assert builder.start_command_value == "libraries/net/neoforged/neoforge/21.1.1-beta/unix_args.txt"


def test_pick_installed_server_jar_prefers_forge_jar_over_vanilla_server_for_legacy_forge(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="Pack",
        mc_version="1.12.2",
        loader="forge",
        loader_version="1.12.2-14.23.5.2860",
    )
    (tmp_path / "forge-1.12.2-14.23.5.2860.jar").write_text("forge", encoding="utf-8")
    (tmp_path / "minecraft_server.1.12.2.jar").write_text("vanilla", encoding="utf-8")
    (tmp_path / "server.jar").write_text("placeholder", encoding="utf-8")

    chosen = ServerBuilder._pick_installed_server_jar(builder)

    assert chosen == "forge-1.12.2-14.23.5.2860.jar"


def test_pick_installed_server_jar_prefers_forge_jar_for_1710_style_name(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="Pack",
        mc_version="1.7.10",
        loader="forge",
        loader_version="1.7.10-10.13.4.1614-1.7.10",
    )
    (tmp_path / "forge-1.7.10-10.13.4.1614-1.7.10.jar").write_text("forge", encoding="utf-8")
    (tmp_path / "minecraft_server.1.7.10.jar").write_text("vanilla", encoding="utf-8")

    chosen = ServerBuilder._pick_installed_server_jar(builder)

    assert chosen == "forge-1.7.10-10.13.4.1614-1.7.10.jar"


def test_build_meta_payload_contains_recognition_and_runtime_state():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.pack_input = type("PackInput", (), {"input_type": "local_zip", "source": "pack.zip", "file_id": None})()
    builder.manifest = PackManifest(
        pack_name="Example Pack",
        mc_version="1.20.1",
        loader="forge",
        loader_version="1.20.1-47.2.0",
        build="47.2.0",
        start_mode="args_file",
        confidence=0.93,
        warnings=["warn"],
        loader_candidates=[DetectionCandidate(value="forge", confidence=0.98)],
    )
    builder.current_java_version = 21
    builder.jvm_xmx = "6G"
    builder.jvm_xms = "4G"
    builder.extra_jvm_flags = ["-XX:+UseG1GC"]
    builder.start_command_mode = "argsfile"
    builder.start_command_value = "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt"
    builder.removed_mods = ["bad.jar"]
    builder.bisect_removed_mods = ["temp.jar"]
    builder.deleted_mod_evidence = {"bad.jar": ["builtin_rule:test"]}
    builder.last_ai_result = None
    builder.last_ai_manual_report = {"user_summary": "manual"}
    builder.attempts_used = 2
    builder.run_success = True
    builder.stop_reason = ""
    builder.recognition_attempts = [{"loader": "forge"}]
    builder.remote_failure_events = [
        {
            "platform": "curseforge",
            "subject": "101:202",
            "operation": "curseforge_mod_meta_missing",
            "stage": "resolve",
            "category": "fallback_miss",
            "exc_type": "",
            "message": "manifest metadata unresolved",
            "context": {"project_id": 101, "file_id": 202},
        }
    ]
    builder.operations = ["op1"]
    builder._build_recognition_summary = ServerBuilder._build_recognition_summary.__get__(builder, ServerBuilder)
    builder._summarize_remote_failure_events = ServerBuilder._summarize_remote_failure_events.__get__(builder, ServerBuilder)
    builder._serialize_detection_candidates = ServerBuilder._serialize_detection_candidates.__get__(builder, ServerBuilder)
    builder.detect_current_java_version = lambda: 21

    payload = ServerBuilder._build_meta_payload(builder)

    assert payload["pack_source"]["input_type"] == "local_zip"
    assert payload["manifest_summary"]["pack_name"] == "Example Pack"
    assert payload["recognition_result"]["active_loader"] == "forge"
    assert payload["java"]["selected_version"] == 21
    assert payload["deleted_mods"]["removed_mods"] == ["bad.jar"]
    assert payload["remote_failures"]["summary"]["total"] == 1
    assert payload["remote_failures"]["summary"]["category_counts"] == {"fallback_miss": 1}
    assert payload["remote_failures"]["events"][0]["operation"] == "curseforge_mod_meta_missing"


def test_extracted_reporting_helpers_match_builder_behavior(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.workdirs = type(
        "W",
        (),
        {
            "root": tmp_path,
            "logs": tmp_path / "logs",
            "server": tmp_path / "server",
            "java_bins": tmp_path / "java_bins",
        },
    )()
    builder.workdirs.logs.mkdir()
    builder.workdirs.server.mkdir()
    builder.workdirs.java_bins.mkdir()
    builder.manifest = PackManifest(
        pack_name="Pack",
        mc_version="1.20.1",
        loader="forge",
        loader_version="47.2.0",
        build="47.2.0",
        start_mode="args_file",
        confidence=0.8,
        warnings=[],
        loader_candidates=[DetectionCandidate(value="forge", confidence=0.9)],
    )
    builder.pack_input = type("PackInput", (), {"input_type": "local_zip", "source": "pack.zip", "file_id": None})()
    builder.recognition_attempts = [{"reason": "runtime_feedback_fallback", "loader": "forge"}]
    builder.current_java_version = 21
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "2G"
    builder.extra_jvm_flags = []
    builder.start_command_mode = "jar"
    builder.start_command_value = "server.jar"
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.deleted_mod_evidence = {}
    builder.deleted_mod_sources = {}
    builder.last_ai_result = None
    builder.last_ai_manual_report = {}
    builder.attempts_used = 1
    builder.run_success = False
    builder.stop_reason = "failed"
    builder.operations = []
    builder.attempt_traces = []
    builder.known_deleted_client_mods = set()
    builder.detect_current_java_version = lambda: 21
    builder.ai_service = BuilderAIService(builder)
    builder._normalize_text_list = ServerBuilder._normalize_text_list.__get__(builder, ServerBuilder)
    builder._extract_log_signal_lines = ServerBuilder._extract_log_signal_lines.__get__(builder, ServerBuilder)
    builder._format_bisect_tree_lines = lambda: ["- none"]
    builder._sanitize_trace_stage = ServerBuilder._sanitize_trace_stage.__get__(builder, ServerBuilder)
    builder._attempt_trace_path = ServerBuilder._attempt_trace_path.__get__(builder, ServerBuilder)
    builder._build_recognition_summary = ServerBuilder._build_recognition_summary.__get__(builder, ServerBuilder)
    builder.remote_failure_events = []
    builder._summarize_remote_failure_events = ServerBuilder._summarize_remote_failure_events.__get__(builder, ServerBuilder)

    context = {"loader": "forge", "mc_version": "1.20.1", "recognition_summary": {"confidence": 0.8}}

    assert attempt_trace_path(builder, 2, "ai stage") == builder.workdirs.logs / "attempt_02_ai_stage.json"
    assert summarize_ai_context(builder, context) == ServerBuilder._summarize_ai_context(builder, context)
    assert build_recognition_summary(builder) == ServerBuilder._build_recognition_summary(builder)
    assert build_meta_payload(builder) == ServerBuilder._build_meta_payload(builder)

    report_path = generate_report(builder)
    package_path = package_server(builder)

    assert Path(report_path).name == "report.txt"
    assert Path(package_path).name == "server_pack.zip"


def test_package_server_embeds_build_meta_json(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.workdirs = type("WorkDirs", (), {"root": tmp_path, "server": tmp_path / "server", "java_bins": tmp_path / "java_bins"})()
    builder.workdirs.server.mkdir()
    builder.workdirs.java_bins.mkdir()
    (builder.workdirs.server / "server.jar").write_text("jar", encoding="utf-8")
    (builder.workdirs.java_bins / "java").write_text("bin", encoding="utf-8")
    builder._build_meta_payload = ServerBuilder._build_meta_payload.__get__(builder, ServerBuilder)
    builder._build_recognition_summary = lambda: {"active_loader": "forge", "confidence": 0.9}
    builder.detect_current_java_version = lambda: 21
    builder.pack_input = type("PackInput", (), {"input_type": "local_zip", "source": "pack.zip", "file_id": None})()
    builder.manifest = PackManifest(pack_name="Pack", mc_version="1.20.1", loader="forge")
    builder.current_java_version = 21
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "2G"
    builder.extra_jvm_flags = []
    builder.start_command_mode = "jar"
    builder.start_command_value = "server.jar"
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.deleted_mod_evidence = {}
    builder.last_ai_result = None
    builder.last_ai_manual_report = {}
    builder.attempts_used = 0
    builder.run_success = False
    builder.stop_reason = ""
    builder.recognition_attempts = []
    builder.operations = []
    builder.remote_failure_events = []
    builder._summarize_remote_failure_events = ServerBuilder._summarize_remote_failure_events.__get__(builder, ServerBuilder)

    out = ServerBuilder.package_server(builder)

    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        assert "build_meta.json" in names
        payload = json.loads(zf.read("build_meta.json").decode("utf-8"))
        assert payload["manifest_summary"]["loader"] == "forge"
        assert payload["remote_failures"]["summary"]["total"] == 0
        assert "server.jar" in names
        assert "java_bins/java" in names


def test_package_server_excludes_runtime_directories(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.workdirs = type("WorkDirs", (), {"root": tmp_path, "server": tmp_path / "server", "java_bins": tmp_path / "java_bins"})()
    builder.workdirs.server.mkdir()
    builder.workdirs.java_bins.mkdir()
    (builder.workdirs.server / "server.jar").write_text("jar", encoding="utf-8")
    (builder.workdirs.server / "logs").mkdir()
    (builder.workdirs.server / "logs" / "latest.log").write_text("log", encoding="utf-8")
    (builder.workdirs.server / "crash-reports").mkdir()
    (builder.workdirs.server / "crash-reports" / "crash-1.txt").write_text("crash", encoding="utf-8")
    (builder.workdirs.server / "world").mkdir()
    (builder.workdirs.server / "world" / "level.dat").write_text("world", encoding="utf-8")
    (builder.workdirs.server / "world_nether").mkdir()
    (builder.workdirs.server / "world_nether" / "level.dat").write_text("nether", encoding="utf-8")
    (builder.workdirs.server / "world_the_end").mkdir()
    (builder.workdirs.server / "world_the_end" / "level.dat").write_text("end", encoding="utf-8")
    (builder.workdirs.java_bins / "java").write_text("bin", encoding="utf-8")
    builder._build_meta_payload = ServerBuilder._build_meta_payload.__get__(builder, ServerBuilder)
    builder._build_recognition_summary = lambda: {"active_loader": "forge", "confidence": 0.9}
    builder.detect_current_java_version = lambda: 21
    builder.pack_input = type("PackInput", (), {"input_type": "local_zip", "source": "pack.zip", "file_id": None})()
    builder.manifest = PackManifest(pack_name="Pack", mc_version="1.20.1", loader="forge")
    builder.current_java_version = 21
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "2G"
    builder.extra_jvm_flags = []
    builder.start_command_mode = "jar"
    builder.start_command_value = "server.jar"
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.deleted_mod_evidence = {}
    builder.last_ai_result = None
    builder.last_ai_manual_report = {}
    builder.attempts_used = 0
    builder.run_success = False
    builder.stop_reason = ""
    builder.recognition_attempts = []
    builder.operations = []
    builder.remote_failure_events = []
    builder._summarize_remote_failure_events = ServerBuilder._summarize_remote_failure_events.__get__(builder, ServerBuilder)

    out = ServerBuilder.package_server(builder)

    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        assert "server.jar" in names
        assert "logs/latest.log" not in names
        assert "crash-reports/crash-1.txt" not in names
        assert "world/level.dat" not in names
        assert "world_nether/level.dat" not in names
        assert "world_the_end/level.dat" not in names


def test_select_next_recognition_plan_uses_runtime_feedback(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.current_java_version = 17
    builder.recognition_attempts = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="pack",
        mc_version="1.20.1",
        loader="fabric",
        loader_candidates=[DetectionCandidate(value="fabric", confidence=0.7), DetectionCandidate(value="forge", confidence=0.6)],
        mc_version_candidates=[DetectionCandidate(value="1.20.1", confidence=0.9)],
        loader_version_candidates=[DetectionCandidate(value="1.20.1-47.2.0", confidence=0.7)],
        start_mode_candidates=[DetectionCandidate(value="jar", confidence=0.4), DetectionCandidate(value="argsfile", confidence=0.8)],
    )
    (tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.20.1-47.2.0").mkdir(parents=True)
    (tmp_path / "server.jar").write_text("jar", encoding="utf-8")

    plan = ServerBuilder._select_next_recognition_plan(
        builder,
        {"stdout_tail": "FML early loading", "stderr_tail": "", "success": False},
        {"refined_log": "Forge Mod Loader detected", "key_exception": ""},
    )

    assert isinstance(plan, RecognitionFallbackPlan)
    assert plan.loader == "forge"
    assert plan.start_mode == "argsfile"
    assert plan.java_version == 17
    assert "runtime_loader=forge" in plan.reason


def test_recognition_runtime_helpers_match_builder_wrappers(tmp_path):
    import mc_auto_server_builder.recognition as recognition_module

    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.current_java_version = 17
    builder.recognition_attempts = []
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder.manifest = PackManifest(
        pack_name="pack",
        mc_version="1.20.1",
        loader="fabric",
        loader_candidates=[DetectionCandidate(value="fabric", confidence=0.7), DetectionCandidate(value="forge", confidence=0.6)],
        mc_version_candidates=[DetectionCandidate(value="1.20.1", confidence=0.9)],
        loader_version_candidates=[DetectionCandidate(value="1.20.1-47.2.0", confidence=0.7)],
        start_mode_candidates=[DetectionCandidate(value="jar", confidence=0.4), DetectionCandidate(value="argsfile", confidence=0.8)],
    )
    (tmp_path / "libraries" / "net" / "minecraftforge" / "forge" / "1.20.1-47.2.0").mkdir(parents=True)
    (tmp_path / "server.jar").write_text("jar", encoding="utf-8")
    builder._build_recognition_candidates = ServerBuilder._build_recognition_candidates.__get__(builder, ServerBuilder)
    builder._preflight_recognition_plan = ServerBuilder._preflight_recognition_plan.__get__(builder, ServerBuilder)
    builder._recognition_runtime_feedback = ServerBuilder._recognition_runtime_feedback.__get__(builder, ServerBuilder)

    start_res = {"stdout_tail": "FML early loading", "stderr_tail": "", "success": False}
    log_info = {"refined_log": "Forge Mod Loader detected", "key_exception": ""}

    assert build_recognition_candidates(
        builder.manifest,
        recognition_module.choose_java_version,
    ) == builder._build_recognition_candidates()
    assert recognition_runtime_feedback(
        start_res,
        log_info,
        builder.current_java_version,
    ) == builder._recognition_runtime_feedback(start_res, log_info)
    assert select_next_recognition_plan(
        start_res=start_res,
        log_info=log_info,
        plans=builder._build_recognition_candidates(),
        recognition_attempts=list(builder.recognition_attempts),
        current_java_version=builder.current_java_version,
        preflight=builder._preflight_recognition_plan,
    ) == ServerBuilder._select_next_recognition_plan(builder, start_res, log_info)


def test_preflight_recognition_plan_reports_confidence_level(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.manifest = PackManifest(pack_name="pack", mc_version="1.20.1", loader="forge")
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    (tmp_path / "libraries" / "net" / "minecraftforge").mkdir(parents=True)
    (tmp_path / "server.jar").write_text("jar", encoding="utf-8")

    result = ServerBuilder._preflight_recognition_plan(
        builder,
        RecognitionFallbackPlan(
            loader="forge",
            loader_version="1.20.1-47.2.0",
            mc_version="1.20.1",
            build="47.2.0",
            start_mode="jar",
            java_version=17,
            confidence=0.52,
            reason="候选识别计划",
            source_candidates=["forge", "1.20.1", "jar"],
        ),
    )

    assert result["allowed"] is True
    assert result["confidence_level"] == "low"
    assert "java_version_matches_loader_strategy" in result["checks"]


def test_preflight_recognition_plan_helper_matches_builder(tmp_path):
    import mc_auto_server_builder.recognition as recognition_module

    builder = ServerBuilder.__new__(ServerBuilder)
    builder.server_jar_name = "server.jar"
    builder.manifest = PackManifest(pack_name="pack", mc_version="1.20.1", loader="forge")
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    (tmp_path / "libraries" / "net" / "minecraftforge").mkdir(parents=True)
    (tmp_path / "server.jar").write_text("jar", encoding="utf-8")
    plan = RecognitionFallbackPlan(
        loader="forge",
        loader_version="1.20.1-47.2.0",
        mc_version="1.20.1",
        build="47.2.0",
        start_mode="jar",
        java_version=17,
        confidence=0.52,
        reason="候选识别计划",
        source_candidates=["forge", "1.20.1", "jar"],
    )

    assert preflight_recognition_plan(
        plan,
        server_dir=tmp_path,
        server_jar_name="server.jar",
        manifest=builder.manifest,
        choose_java=recognition_module.choose_java_version,
    ) == ServerBuilder._preflight_recognition_plan(builder, plan)


def test_normalize_ai_result_accepts_switch_recognition_candidate_action():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    result = service._normalize_ai_result(
        {
            "final_output": {
                "primary_issue": "loader_misclassification",
                "confidence": 0.81,
                "reason": "日志出现明显 Forge 特征",
                "actions": [
                    {
                        "type": "switch_recognition_candidate",
                        "loader": "forge",
                        "loader_version": "1.20.1-47.2.0",
                        "mc_version": "1.20.1",
                        "start_mode": "argsfile",
                    }
                ],
            }
        }
    )

    assert result.primary_issue == "loader_misclassification"
    assert result.actions[0].type == "switch_recognition_candidate"
    assert result.actions[0].loader == "forge"


def test_build_recognition_summary_includes_candidates_and_evidence_preview():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = type(
        "Manifest",
        (),
        {
            "pack_name": "demo-pack",
            "confidence": 0.91,
            "warnings": ["low build confidence"],
            "loader_candidates": [
                DetectionCandidate(value="forge", confidence=0.98, reason="manifest.json"),
            ],
            "mc_version_candidates": [
                DetectionCandidate(value="1.20.1", confidence=0.97, reason="manifest.json"),
            ],
            "loader_version_candidates": [
                DetectionCandidate(value="1.20.1-47.2.0", confidence=0.95, reason="script"),
            ],
            "build_candidates": [
                DetectionCandidate(value="47.2.0", confidence=0.9, reason="derived"),
            ],
            "start_mode_candidates": [
                DetectionCandidate(value="args_file", confidence=0.92, reason="run.sh"),
            ],
            "evidence": [
                DetectionEvidence(
                    source_type="script",
                    evidence_type="args_path",
                    file="run.sh",
                    matched_text="@libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt",
                    weight=0.94,
                    reason="命中 Forge args 路径",
                )
            ],
            "raw": {
                "recognition_pipeline": [
                    "explicit_metadata",
                    "startup_script",
                    "file_pattern",
                    "directory_feature",
                    "text_heuristic",
                    "runtime_feedback",
                ],
                "recognition_phase_hits": ["explicit_metadata", "startup_script"],
                "recognition_phase_details": {"explicit_metadata": ["variables:variables.txt"]},
            },
        },
    )()

    summary = ServerBuilder._build_recognition_summary(builder)

    assert summary["pack_name"] == "demo-pack"
    assert summary["confidence"] == 0.91
    assert summary["loader_candidates"][0]["value"] == "forge"
    assert summary["start_mode_candidates"][0]["value"] == "args_file"
    assert summary["evidence_preview"][0]["file"] == "run.sh"
    assert summary["recognition_pipeline"][0] == "explicit_metadata"
    assert "startup_script" in summary["recognition_phase_hits"]


def test_detect_failure_signals_matches_extended_runtime_errors():
    builder = ServerBuilder.__new__(ServerBuilder)

    result = ServerBuilder._detect_failure_signals(
        builder,
        (
            "Could not reserve enough space for 4096KB object heap\n"
            "Argument file @libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt not found"
        ),
    )

    assert "memory_allocation" in result
    assert "loader_misclassification" in result


def test_generate_report_contains_deleted_mod_source_breakdown(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.workdirs = type("W", (), {"root": tmp_path})()
    builder.run_success = False
    builder.attempts_used = 1
    builder.stop_reason = "failed"
    builder.removed_mods = ["client.jar"]
    builder.bisect_removed_mods = []
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.last_ai_result = None
    builder.last_ai_manual_report = {}
    builder.known_deleted_client_mods = {"client.jar"}
    builder.deleted_mod_evidence = {"client.jar": ["builtin_rule:client_only"]}
    builder.deleted_mod_sources = {
        "client.jar": {
            "builtin_rule": ["builtin_rule:client_only"],
            "user_rule": [],
            "ai_suggested": [],
            "dependency_cleanup": [],
            "bisect": [],
            "other": [],
        }
    }
    builder.attempt_traces = []
    builder.operations = []
    builder.detect_current_java_version = lambda: 21
    builder._attempt_trace_path = lambda attempt, stage: tmp_path / f"{attempt}_{stage}.json"
    builder._format_bisect_tree_lines = lambda: ["- none"]
    builder._build_recognition_summary = lambda: {
        "pack_name": "demo",
        "active_loader": "forge",
        "active_mc_version": "1.20.1",
        "active_loader_version": None,
        "active_build": None,
        "active_start_mode": "jar",
        "confidence": 0.5,
        "loader_candidates": [],
        "mc_version_candidates": [],
        "build_candidates": [],
        "start_mode_candidates": [],
        "recognition_pipeline": [],
        "recognition_phase_hits": [],
        "recognition_phase_details": {},
        "fallback_history": [],
        "evidence_preview": [],
    }
    builder.remote_failure_events = [
        {
            "platform": "modrinth",
            "subject": "mods/no-url.jar",
            "operation": "modrinth_manifest_fill_no_url",
            "stage": "resolve_url",
            "category": "no_url",
            "exc_type": "",
            "message": "downloads missing",
            "context": {"path": "mods/no-url.jar", "project_id": "proj", "file_id": "ver"},
        },
        {
            "platform": "curseforge",
            "subject": "101:202",
            "operation": "curseforge_mod_meta_missing",
            "stage": "resolve",
            "category": "fallback_miss",
            "exc_type": "",
            "message": "manifest metadata unresolved",
            "context": {"project_id": 101, "file_id": 202},
        },
    ]
    builder._summarize_remote_failure_events = ServerBuilder._summarize_remote_failure_events.__get__(builder, ServerBuilder)

    report_path = ServerBuilder.generate_report(builder)
    report_text = (tmp_path / "report.txt").read_text(encoding="utf-8")

    assert report_path
    assert "删除 mod 来源分层统计:" in report_text
    assert '"builtin_rule": ["builtin_rule:client_only"]' in report_text
    assert "远端失败事件摘要:" in report_text
    assert '"fallback_miss": 1' in report_text
    assert '"no_url": 1' in report_text
    assert "最近远端失败明细:" in report_text
    assert "operation=curseforge_mod_meta_missing" in report_text
    assert 'context={"project_id": 101, "file_id": 202}' in report_text


def test_summarize_remote_failure_events_groups_counts_and_recent_details():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.remote_failure_events = [
        {
            "platform": "temurin",
            "subject": "17",
            "operation": "temurin_download_or_extract",
            "stage": "download_or_extract",
            "category": "download",
            "exc_type": "BadZipFile",
            "message": "bad archive",
            "context": {"url": "https://example.invalid/jdk17.zip"},
        },
        {
            "platform": "curseforge",
            "subject": "101:202",
            "operation": "curseforge_mod_meta_missing",
            "stage": "resolve",
            "category": "fallback_miss",
            "exc_type": "",
            "message": "manifest metadata unresolved",
        },
        {
            "platform": "curseforge",
            "subject": "102:203",
            "operation": "curseforge_mod_no_url",
            "stage": "resolve_url",
            "category": "no_url",
            "exc_type": "",
            "message": "download URL missing",
        },
    ]

    summary = ServerBuilder._summarize_remote_failure_events(builder, detail_limit=2)

    assert summary["total"] == 3
    assert summary["platform_counts"] == {"curseforge": 2, "temurin": 1}
    assert summary["category_counts"] == {"download": 1, "fallback_miss": 1, "no_url": 1}
    assert summary["operation_counts"]["temurin_download_or_extract"] == 1
    assert summary["stage_counts"] == {"download_or_extract": 1, "resolve": 1, "resolve_url": 1}
    assert len(summary["recent_events"]) == 2
    assert summary["recent_events"][0]["operation"] == "curseforge_mod_meta_missing"
    assert summary["recent_events"][1]["operation"] == "curseforge_mod_no_url"


def test_summarize_ai_context_includes_recognition_summary():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._normalize_text_list = ServerBuilder._normalize_text_list.__get__(builder, ServerBuilder)
    builder._extract_log_signal_lines = ServerBuilder._extract_log_signal_lines.__get__(builder, ServerBuilder)
    builder.ai_service = BuilderAIService(builder)

    summary = ServerBuilder._summarize_ai_context(
        builder,
        {
            "mc_version": "1.20.1",
            "loader": "forge",
            "loader_version": "1.20.1-47.2.0",
            "build": "47.2.0",
            "start_mode": "args_file",
            "mod_count": 5,
            "current_installed_mods": ["a.jar", "b.jar"],
            "recognition_summary": {
                "confidence": 0.88,
                "loader_candidates": [{"value": "forge"}],
            },
        },
    )

    assert summary["loader_version"] == "1.20.1-47.2.0"
    assert summary["build"] == "47.2.0"
    assert summary["start_mode"] == "args_file"
    assert summary["recognition_summary"]["confidence"] == 0.88


def test_build_ai_context_helper_matches_builder_wrapper():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(pack_name="pack", mc_version="1.20.1", loader="forge", loader_version="1.20.1-47.2.0", build="47.2.0")
    builder.jvm_xmx = "8G"
    builder.jvm_xms = "4G"
    builder.known_deleted_client_mods = {"client-only.jar"}
    builder.deleted_mod_evidence = {"client-only.jar": ["rule"]}
    builder.operations = ["a", "b"]
    builder.last_rollback_remove_mods = {
        "triggered": True,
        "crash_reports_after_validation": ["crash-1.txt"],
        "validation_crash_excerpt": "boom",
    }
    builder.remove_validation_state = {"continue_allowed": True}
    builder.last_bisect_feedback = {"status": "same_issue"}
    builder._coerce_bisect_session = lambda: BisectSession(
        active=True,
        phase="fallback",
        fallback_targets=["a.jar"],
        next_allowed_requests=["initial"],
    )
    builder._build_recognition_summary = lambda: {"confidence": 0.88}
    builder.get_system_memory = lambda: 16.0
    builder.list_mods = lambda: ["a.jar", "b.jar"]
    builder.list_current_installed_client_mods = lambda: ["client-only.jar"]

    start_res = {
        "crash_reports_snapshot": ["crash-2.txt"],
        "done_detected": False,
        "command_probe_detected": False,
        "port_open_detected": False,
        "stdout_tail": "stdout",
        "stderr_tail": "stderr",
    }
    log_info = {"refined_log": "line1", "key_exception": "KeyError"}

    assert build_ai_context(builder, start_res, log_info) == ServerBuilder._build_ai_context(builder, start_res, log_info)


def test_build_prompt_allows_initial_bisect_when_session_inactive():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.config = type("Cfg", (), {"ai": type("AI", (), {"enabled": False, "debug": False})()})()
    service = BuilderAIService(builder)

    prompt = service.build_prompt(
        {
            "bisect_active": False,
            "bisect_next_allowed_requests": [],
            "current_installed_mods": ["a.jar", "b.jar", "c.jar"],
        }
    )

    assert "若 bisect_state.active=false，且仍有至少 2 个可疑 mod，则允许发起 initial" in prompt


def test_assess_action_preflight_allows_controlled_bisect():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "lib.jar"]
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {
            "type": "bisect_mods",
            "targets": ["a.jar", "b.jar", "lib.jar"],
            "move_candidates": ["lib.jar"],
        },
    )

    assert preflight.allowed is True
    assert preflight.reason == "controlled_bisect_allowed"


def test_run_bisect_mods_action_moves_dependency_and_restores_snapshot():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.bisect_session = BisectSession()
    builder.last_bisect_feedback = {}
    builder._log = lambda *_args, **_kwargs: None
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)
    builder._make_bisect_progress_token = ServerBuilder._make_bisect_progress_token.__get__(builder, ServerBuilder)

    state = {"mods": ["a.jar", "b.jar", "lib.jar"]}

    def list_mods():
        return list(state["mods"])

    def backup_mods(_tag: str):
        return None

    def rollback_mods(_tag: str):
        state["mods"] = ["a.jar", "b.jar", "lib.jar"]

    def remove_mods_by_name(names: list[str], source: str = "manual", reason: str = ""):
        state["mods"] = [m for m in state["mods"] if m not in names]
        builder.operations.append(f"removed:{source}:{reason}:{','.join(names)}")

    def start_server(timeout: int = 300):
        active = set(state["mods"])
        return {"success": active == {"a.jar", "lib.jar"}}

    builder.list_mods = list_mods
    builder.backup_mods = backup_mods
    builder.rollback_mods = rollback_mods
    builder.remove_mods_by_name = remove_mods_by_name
    builder.start_server = start_server

    stop, execution, rollback = ServerBuilder._run_bisect_mods_action(
        builder,
        1,
        {
            "type": "bisect_mods",
            "bisect_mode": "initial",
            "targets": ["a.jar", "b.jar", "lib.jar"],
            "bisect_reason": "申请稳定二分并在必要时修正依赖",
            "move_candidates": ["lib.jar"],
            "allow_dependency_moves": True,
        },
        "attempt_1_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert execution["tested_side"] == "keep"
    assert execution["keep_group"] == ["a.jar"]
    assert execution["test_group"] == ["b.jar", "lib.jar"]
    assert execution["moved_mods"] == ["lib.jar"]
    assert execution["startup_success"] is True
    assert execution["next_suspects"] == ["b.jar", "lib.jar"]
    assert execution["already_bisected"] is True
    assert execution["next_allowed_requests"] == ["switch_group"]
    assert state["mods"] == ["a.jar", "b.jar", "lib.jar"]
    assert builder.removed_mods == []
    assert builder.bisect_removed_mods == []
    assert builder.bisect_session.rounds[0].moved_mods[0].mod_name == "lib.jar"
    assert builder.bisect_session.last_round_feedback["split_strategy"] == "stable_sorted_halves"
    assert builder.bisect_session.pending_group == ["b.jar", "lib.jar"]


def test_remove_mods_by_name_separates_bisect_removals(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.operations = []
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder._log = lambda *_args, **_kwargs: None
    builder._record_deleted_client_mod = ServerBuilder._record_deleted_client_mod.__get__(builder, ServerBuilder)
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    mods_dir = tmp_path / "mods"
    mods_dir.mkdir()
    (mods_dir / "a.jar").write_text("x", encoding="utf-8")
    (mods_dir / "b.jar").write_text("x", encoding="utf-8")

    ServerBuilder.remove_mods_by_name(builder, ["a.jar"], source="bisect", reason="test")
    ServerBuilder.remove_mods_by_name(builder, ["b.jar"], source="manual", reason="final")

    assert builder.bisect_removed_mods == ["a.jar"]
    assert builder.removed_mods == ["b.jar"]


def test_apply_recognition_based_client_cleanup_removes_known_client_mods(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.removed_mods = []
    builder.bisect_removed_mods = []
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.deleted_mod_sources = {}
    builder.manifest = PackManifest(pack_name="demo", mc_version="1.20.1", loader="forge")
    builder._log = lambda *_args, **_kwargs: None
    builder._record_deleted_client_mod = ServerBuilder._record_deleted_client_mod.__get__(builder, ServerBuilder)
    builder._record_deleted_mod_detail = ServerBuilder._record_deleted_mod_detail.__get__(builder, ServerBuilder)
    builder.remove_mods_by_name = ServerBuilder.remove_mods_by_name.__get__(builder, ServerBuilder)
    builder.apply_recognition_based_client_cleanup = ServerBuilder.apply_recognition_based_client_cleanup.__get__(builder, ServerBuilder)
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    mods_dir = tmp_path / "mods"
    mods_dir.mkdir()
    (mods_dir / "fancymenu-3.0.jar").write_text("x", encoding="utf-8")
    (mods_dir / "servercore-1.0.jar").write_text("x", encoding="utf-8")

    removed = builder.apply_recognition_based_client_cleanup()

    assert removed == ["fancymenu-3.0.jar"]
    assert not (mods_dir / "fancymenu-3.0.jar").exists()
    assert (mods_dir / "servercore-1.0.jar").exists()


def test_install_server_core_uses_split_loader_branches():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(pack_name="demo", mc_version="1.20.1", loader="quilt", loader_version="0.25.1")
    builder.operations = []
    called: list[str] = []
    builder._install_forge_like_server = lambda **kwargs: called.append(f"forge:{kwargs['loader']}")
    builder._install_fabric_like_server = lambda **kwargs: called.append(f"fabric:{kwargs['loader']}")

    ServerBuilder._install_server_core(builder)

    assert called == ["fabric:quilt"]


def test_install_server_core_recovers_existing_forge_jar_when_installer_fails(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.manifest = PackManifest(
        pack_name="demo",
        mc_version="1.12.2",
        loader="forge",
        loader_version="1.12.2-14.23.5.2860",
    )
    builder.operations = []
    builder.server_jar_name = "server.jar"
    builder.start_command_mode = "jar"
    builder.start_command_value = builder.server_jar_name
    builder.workdirs = type("WorkDirs", (), {"server": tmp_path})()
    builder._set_start_command = ServerBuilder._set_start_command.__get__(builder, ServerBuilder)
    builder._pick_installed_server_jar = ServerBuilder._pick_installed_server_jar.__get__(builder, ServerBuilder)
    builder._recover_start_command_from_existing_server_artifacts = (
        ServerBuilder._recover_start_command_from_existing_server_artifacts.__get__(builder, ServerBuilder)
    )
    builder._parse_start_command_from_run_scripts = lambda: False
    builder._apply_modern_loader_start_mode = lambda: False
    builder._install_forge_like_server = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("installer failed"))
    builder._install_fabric_like_server = lambda **_kwargs: None
    (tmp_path / "forge-1.12.2-14.23.5.2860.jar").write_text("forge", encoding="utf-8")

    ServerBuilder._install_server_core(builder)

    assert builder.server_jar_name == "forge-1.12.2-14.23.5.2860.jar"
    assert builder.start_command_value == "forge-1.12.2-14.23.5.2860.jar"
    assert not (tmp_path / "server.jar").exists()
    assert any(op == "install_server_core:forge:failed:RuntimeError" for op in builder.operations)
    assert any(op.startswith("start_command_recovered:jar:forge-1.12.2-14.23.5.2860.jar") for op in builder.operations)


def test_extract_latest_crash_mod_issue_returns_latest_section():
    builder = ServerBuilder.__new__(ServerBuilder)

    text = """
header
-- Mod loading issue for: oldmod --
Details:
    old block
-- System Details --
tail
-- Mod loading issue for: fancymenu --
Details:
    Mod file: /D:/GAME/workdir/server/mods/fancymenu.jar
    Failure message: Mod fancymenu requires konkrete 1.9.4 or above
        Currently, konkrete is not installed

    Mod version: 3.8.1
    Exception message: <No associated exception found>
-- System Details --
"""

    result = ServerBuilder._extract_latest_crash_mod_issue(builder, text)

    assert result.startswith("-- Mod loading issue for: fancymenu --")
    assert "Failure message: Mod fancymenu requires konkrete 1.9.4 or above" in result
    assert "Currently, konkrete is not installed" in result
    assert "oldmod" not in result


def test_assess_action_preflight_blocks_duplicate_bisect_request_after_feedback():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "lib.jar"]
    builder.last_bisect_feedback = {"requested_targets": ["a.jar", "b.jar", "lib.jar"]}
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {
            "type": "bisect_mods",
            "targets": ["a.jar", "b.jar", "lib.jar"],
        },
    )

    assert preflight.allowed is False
    assert preflight.reason == "duplicate_bisect_request_after_previous_round"


def test_assess_action_preflight_allows_system_auto_resume_fallback_initial():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "c.jar", "d.jar"]
    builder.last_bisect_feedback = {"requested_targets": ["a.jar", "b.jar"]}
    builder.bisect_session = BisectSession(
        active=True,
        phase="fallback",
        suspects_invalidated=True,
        fallback_targets=["a.jar", "b.jar", "c.jar", "d.jar"],
        next_allowed_requests=["initial"],
        completed_requests=["initial"],
    )
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {
            "type": "bisect_mods",
            "bisect_mode": "initial",
            "targets": ["a.jar", "b.jar", "c.jar", "d.jar"],
            "request_source": "system_auto_resume",
        },
    )

    assert preflight.allowed is True
    assert preflight.reason == "controlled_bisect_allowed"


def test_assess_action_preflight_allows_switch_group_only_when_feedback_exposes_it():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "lib.jar"]
    builder.last_bisect_feedback = {}
    builder.bisect_session = BisectSession(
        pending_group=["b.jar", "lib.jar"],
        next_allowed_requests=["switch_group"],
        completed_requests=["initial"],
    )
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {"type": "bisect_mods", "bisect_mode": "switch_group", "bisect_reason": "切换验证另一组"},
    )

    assert preflight.allowed is True
    assert preflight.reason == "controlled_bisect_allowed"


def test_run_bisect_mods_action_switch_group_can_fail_and_enable_continuation():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder.last_bisect_feedback = {}
    builder._log = lambda *_args, **_kwargs: None
    builder.bisect_session = BisectSession(
        pending_group=["b.jar", "c.jar", "lib.jar", "x.jar"],
        next_allowed_requests=["switch_group"],
        completed_requests=["initial"],
    )
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)
    builder._make_bisect_progress_token = ServerBuilder._make_bisect_progress_token.__get__(builder, ServerBuilder)

    state = {"mods": ["a.jar", "b.jar", "c.jar", "lib.jar", "x.jar"]}

    builder.list_mods = lambda: list(state["mods"])
    builder.backup_mods = lambda _tag: None
    builder.rollback_mods = lambda _tag: state.__setitem__("mods", ["a.jar", "b.jar", "c.jar", "lib.jar", "x.jar"])
    builder.remove_mods_by_name = lambda names, source="manual", reason="": state.__setitem__(
        "mods",
        [m for m in state["mods"] if m not in names],
    )
    builder.start_server = lambda timeout=300: {"success": False, "stderr_tail": "missing dependency for lib.jar"}

    stop, execution, rollback = ServerBuilder._run_bisect_mods_action(
        builder,
        1,
        {"type": "bisect_mods", "bisect_mode": "switch_group", "bisect_reason": "切换验证另一组"},
        "attempt_2_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["tested_side"] == "test"
    assert execution["status"] == "applied"
    assert execution["failure_kind"] == "dependency_failure"
    assert "continue_failed_group" in execution["next_allowed_requests"]
    assert builder.bisect_session.continuation_targets == ["lib.jar", "x.jar"]


def test_assess_action_preflight_blocks_switch_group_when_not_allowed():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "lib.jar"]
    builder.last_bisect_feedback = {}
    builder.bisect_session = BisectSession(next_allowed_requests=["continue_failed_group"], completed_requests=["initial"])
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {"type": "bisect_mods", "bisect_mode": "switch_group"},
    )

    assert preflight.allowed is False
    assert preflight.reason == "bisect_request_not_allowed_in_current_state"


def test_run_bisect_mods_action_initial_success_invalidates_ai_suspects_and_requests_full_fallback():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder.last_bisect_feedback = {}
    builder._log = lambda *_args, **_kwargs: None
    builder.bisect_session = BisectSession(source_mods=["a.jar", "b.jar", "c.jar", "d.jar"])
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)
    builder._make_bisect_progress_token = ServerBuilder._make_bisect_progress_token.__get__(builder, ServerBuilder)

    state = {"mods": ["a.jar", "b.jar", "c.jar", "d.jar"]}
    builder.list_mods = lambda: list(state["mods"])
    builder.backup_mods = lambda _tag: None
    builder.rollback_mods = lambda _tag: state.__setitem__("mods", ["a.jar", "b.jar", "c.jar", "d.jar"])
    builder.remove_mods_by_name = lambda names, source="manual", reason="": state.__setitem__(
        "mods",
        [m for m in state["mods"] if m not in names],
    )
    builder.start_server = lambda timeout=300: {"success": True, "success_source": "log_done"}

    stop, execution, rollback = ServerBuilder._run_bisect_mods_action(
        builder,
        1,
        {"type": "bisect_mods", "bisect_mode": "initial", "targets": ["a.jar", "b.jar"], "bisect_reason": "AI 猜测这两项最可疑"},
        "attempt_1_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert execution["suspects_invalidated"] is True
    assert execution["fallback_targets"] == ["a.jar", "b.jar", "c.jar", "d.jar"]
    assert execution["next_allowed_requests"] == ["initial"]
    assert builder.bisect_session.suspects_invalidated is True
    assert builder.bisect_session.phase == "initial"
    assert builder.bisect_session.fallback_targets == ["a.jar", "b.jar", "c.jar", "d.jar"]


def test_run_bisect_mods_action_auto_resume_initial_enters_fallback_phase_and_tracks_token():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder.last_bisect_feedback = {}
    builder._log = lambda *_args, **_kwargs: None
    builder.bisect_session = BisectSession(
        active=True,
        source_mods=["a.jar", "b.jar", "c.jar", "d.jar"],
        phase="fallback",
        suspects_invalidated=True,
        fallback_targets=["a.jar", "b.jar", "c.jar", "d.jar"],
        next_allowed_requests=["initial"],
        completed_requests=["initial"],
    )
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)
    builder._make_bisect_progress_token = ServerBuilder._make_bisect_progress_token.__get__(builder, ServerBuilder)

    state = {"mods": ["a.jar", "b.jar", "c.jar", "d.jar"]}
    builder.list_mods = lambda: list(state["mods"])
    builder.backup_mods = lambda _tag: None
    builder.rollback_mods = lambda _tag: state.__setitem__("mods", ["a.jar", "b.jar", "c.jar", "d.jar"])
    builder.remove_mods_by_name = lambda names, source="manual", reason="": state.__setitem__(
        "mods",
        [m for m in state["mods"] if m not in names],
    )
    builder.start_server = lambda timeout=300: {"success": True, "success_source": "log_done"}

    stop, execution, rollback = ServerBuilder._run_bisect_mods_action(
        builder,
        2,
        {
            "type": "bisect_mods",
            "bisect_mode": "initial",
            "targets": ["a.jar", "b.jar", "c.jar", "d.jar"],
            "request_source": "system_auto_resume",
            "bisect_reason": "自动恢复 fallback 二分",
        },
        "attempt_2_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert builder.bisect_session.phase == "fallback"
    assert any(token.startswith("initial:fallback:") for token in builder.bisect_session.completed_request_tokens)


def test_bisect_runtime_prepare_round_plan_matches_builder_shape():
    session = BisectSession(rounds=[BisectRoundRecord(round_index=1)])

    plan, execution = prepare_bisect_round_plan(
        idx=2,
        snapshot_tag="attempt_2_action_1",
        action={"bisect_reason": "切换到当前轮"},
        bisect_mode="switch_group",
        suspects=["a.jar", "b.jar", "c.jar"],
        session=session,
        source_mods=["a.jar", "b.jar", "c.jar"],
        keep_group=["a.jar"],
        test_group=["b.jar", "c.jar"],
    )

    assert plan["tested_side"] == "test"
    assert plan["active_group"] == ["b.jar", "c.jar"]
    assert plan["round_index"] == 2
    assert execution["status"] == "prepared"
    assert execution["suspects"] == ["a.jar", "b.jar", "c.jar"]


def test_bisect_runtime_store_pending_round_plan_preserves_existing_session_fields():
    session = BisectSession(active=True, pending_group=["a.jar"], success_ready=True)

    updated = store_pending_bisect_round_plan(session, {"index": 1, "suspects": ["a.jar", "b.jar"]})

    assert updated.active is True
    assert updated.pending_group == ["a.jar"]
    assert updated.success_ready is True
    assert updated.pending_round_plan == {"index": 1, "suspects": ["a.jar", "b.jar"]}


def test_bisect_runtime_derive_followups_for_switch_and_fallback_paths():
    (
        final_suspects,
        pending_group,
        continuation_targets,
        next_allowed_requests,
        fallback_targets,
        suspects_invalidated,
    ) = derive_bisect_followups(
        bisect_mode="initial",
        tested_side="keep",
        round_result="pass",
        failure_kind="",
        keep_group=["a.jar"],
        test_group=["b.jar"],
        active_after_setup=["a.jar"],
        suspects=["a.jar", "b.jar"],
        source_mods=["a.jar", "b.jar", "c.jar", "d.jar"],
    )

    assert final_suspects == ["a.jar", "b.jar", "c.jar", "d.jar"]
    assert pending_group == []
    assert continuation_targets == []
    assert next_allowed_requests == ["initial"]
    assert fallback_targets == ["a.jar", "b.jar", "c.jar", "d.jar"]
    assert suspects_invalidated is True


def test_bisect_runtime_build_round_record_uses_model_objects():
    session = BisectSession(rounds=[])
    round_record = build_bisect_round_record(
        session=session,
        plan={"round_index": 1, "bisect_reason": "测试依赖迁移"},
        suspects=["a.jar", "b.jar"],
        bisect_mode="initial",
        tested_side="keep",
        keep_group=["a.jar"],
        test_group=["b.jar"],
        moved_mods=["lib.jar"],
        round_result="fail",
        start_res={"success": False},
        failure_kind="dependency_failure",
        failure_detail="missing lib.jar",
        continuation_targets=["a.jar", "lib.jar"],
        pending_group=[],
        next_allowed_requests=["continue_failed_group", "dependency_move_exception"],
        fallback_targets=[],
        suspects_invalidated=False,
        notes=["moved_dependency_candidates"],
    )

    assert isinstance(round_record, BisectRoundRecord)
    assert round_record.moved_mods == [
        BisectMoveRecord(
            mod_name="lib.jar",
            from_group="test",
            to_group="keep",
            reason="startup_dependency_probe",
        )
    ]
    assert round_record.failure_kind == "dependency_failure"
    assert "start_success=False" in round_record.notes


def test_bisect_runtime_update_session_after_round_clears_pending_plan_and_limits_final_suspects():
    session = BisectSession(active=True, rounds=[], pending_round_plan={"index": 2})
    round_record = BisectRoundRecord(round_index=1, result="pass")

    updated = update_bisect_session_after_round(
        session=session,
        source_mods=["a.jar", "b.jar", "c.jar", "d.jar"],
        final_suspects=["a.jar", "b.jar", "c.jar", "d.jar"],
        round_record=round_record,
        feedback={"status": "ok"},
        pending_group=["c.jar", "d.jar"],
        continuation_targets=[],
        next_allowed_requests=["switch_group"],
        completed_requests=["initial"],
        fallback_targets=[],
        suspects_invalidated=False,
        progress_token="token-1",
        stagnant_rounds=0,
    )

    assert updated.active is True
    assert updated.rounds[-1] is round_record
    assert updated.final_suspects == ["a.jar", "b.jar", "c.jar"]
    assert updated.pending_round_plan == {}
    assert updated.safe_mods == []


def test_bisect_runtime_feedback_payload_and_execution_summary_match_builder_contract():
    feedback = build_bisect_feedback_payload(
        suspects=["a.jar", "b.jar"],
        bisect_mode="initial",
        tested_side="keep",
        keep_group=["a.jar"],
        test_group=["b.jar"],
        moved_mods=["lib.jar"],
        round_result="fail",
        startup_success=False,
        failure_kind="dependency_failure",
        failure_detail="missing dependency for lib.jar",
        reason="验证 keep 组",
        pending_group=[],
        continuation_targets=["a.jar", "lib.jar"],
        next_allowed_requests=["continue_failed_group", "dependency_move_exception"],
        fallback_targets=[],
        suspects_invalidated=False,
    )

    execution = summarize_bisect_round_outcome(
        idx=3,
        snapshot_tag="attempt_3_action_1",
        tested_side="keep",
        keep_group=["a.jar"],
        test_group=["b.jar"],
        moved_mods=["lib.jar"],
        final_suspects=["a.jar", "lib.jar"],
        round_result="fail",
        startup_success=False,
        failure_kind="dependency_failure",
        next_allowed_requests=["continue_failed_group", "dependency_move_exception"],
        fallback_targets=[],
        suspects_invalidated=False,
        feedback=feedback,
    )

    assert feedback["grouping_explanation"] == "系统先按文件名稳定排序，再平分为 keep_group(1) 和 test_group(1)；本轮实际验证侧=keep。"
    assert execution["status"] == "applied"
    assert execution["next_suspects"] == ["a.jar", "lib.jar"]
    assert execution["feedback"] is feedback


def test_bisect_runtime_prepare_session_round_update_detects_stagnation_and_preserves_update_inputs():
    session = BisectSession(completed_requests=["initial"], progress_token="same-token", stagnant_rounds=1)
    round_record = BisectRoundRecord(round_index=2, tested_side="keep", result="pass", notes=["start_success=True"])
    feedback = {"result": "pass"}

    update_payload = prepare_bisect_session_round_update(
        session=session,
        bisect_mode="switch_group",
        suspects=["a.jar", "b.jar"],
        source_mods=["a.jar", "b.jar"],
        final_suspects=["b.jar"],
        round_result="pass",
        round_record=round_record,
        feedback=feedback,
        pending_group=["b.jar"],
        continuation_targets=[],
        next_allowed_requests=["switch_group"],
        fallback_targets=[],
        suspects_invalidated=False,
    )

    expected_token = make_bisect_progress_token(
        suspects=["a.jar", "b.jar"],
        bisect_mode="switch_group",
        tested_side="keep",
        round_result="pass",
        final_suspects=["b.jar"],
        next_allowed_requests=["switch_group"],
    )
    same_token_payload = prepare_bisect_session_round_update(
        session=BisectSession(completed_requests=["initial"], progress_token=expected_token, stagnant_rounds=1),
        bisect_mode="switch_group",
        suspects=["a.jar", "b.jar"],
        source_mods=["a.jar", "b.jar"],
        final_suspects=["b.jar"],
        round_result="pass",
        round_record=BisectRoundRecord(round_index=2, tested_side="keep", result="pass", notes=["start_success=True"]),
        feedback=feedback,
        pending_group=["b.jar"],
        continuation_targets=[],
        next_allowed_requests=["switch_group"],
        fallback_targets=[],
        suspects_invalidated=False,
    )

    assert update_payload["completed_requests"] == ["initial", "switch_group"]
    assert update_payload["progress_token"] == expected_token
    assert update_payload["stagnant_rounds"] == 0
    assert same_token_payload["stagnant_rounds"] == 2
    assert "stagnant_round_detected=2" in same_token_payload["round_record"].notes


def test_execute_pending_bisect_round_uses_runtime_shaping_and_clears_pending_plan():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"start_timeout": 5})()})()
    builder.operations = []
    builder.removed_mods = []
    builder.last_bisect_feedback = {}
    builder._log = lambda *_args, **_kwargs: None
    builder.bisect_session = BisectSession(active=True, pending_round_plan={"index": 1}, completed_requests=["initial"])
    builder._coerce_bisect_session = ServerBuilder._coerce_bisect_session.__get__(builder, ServerBuilder)
    builder._classify_bisect_failure = ServerBuilder._classify_bisect_failure.__get__(builder, ServerBuilder)
    builder._derive_bisect_followups = ServerBuilder._derive_bisect_followups.__get__(builder, ServerBuilder)
    builder._build_bisect_feedback_payload = ServerBuilder._build_bisect_feedback_payload.__get__(builder, ServerBuilder)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)

    state = {"mods": ["a.jar", "b.jar", "lib.jar"]}
    builder.list_mods = lambda: list(state["mods"])
    builder.backup_mods = lambda _tag: None
    builder.rollback_mods = lambda _tag: state.__setitem__("mods", ["a.jar", "b.jar", "lib.jar"])
    builder.remove_mods_by_name = lambda names, source="manual", reason="": state.__setitem__(
        "mods",
        [m for m in state["mods"] if m not in names],
    )
    builder.start_server = lambda timeout=300: {"success": False, "stderr_tail": "missing dependency for lib.jar"}

    stop, execution, rollback = ServerBuilder._execute_pending_bisect_round(
        builder,
        {
            "index": 2,
            "snapshot_tag": "attempt_2_action_1",
            "bisect_mode": "switch_group",
            "tested_side": "test",
            "keep_group": ["a.jar"],
            "test_group": ["b.jar", "lib.jar"],
            "suspects": ["a.jar", "b.jar", "lib.jar"],
            "source_mods": ["a.jar", "b.jar", "lib.jar"],
            "active_group": ["b.jar", "lib.jar"],
            "moved_mods": ["lib.jar"],
            "notes": ["moved_dependency_candidates"],
            "bisect_reason": "切换验证另一组",
            "round_index": 2,
        },
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert execution["failure_kind"] == "dependency_failure"
    assert execution["next_allowed_requests"] == ["continue_failed_group", "dependency_move_exception"]
    assert builder.last_bisect_feedback["continuation_targets"] == ["b.jar", "lib.jar"]
    assert builder.bisect_session.pending_round_plan == {}
    assert builder.bisect_session.continuation_targets == ["b.jar", "lib.jar"]
    assert builder.bisect_session.completed_requests == ["initial", "switch_group"]


def test_bisect_runtime_update_session_fields_preserves_model_shape():
    session = BisectSession(active=True, fallback_targets=["a.jar"])

    updated = update_bisect_session_fields(session, active=False, success_ready=True, fallback_targets=[])

    assert isinstance(updated, BisectSession)
    assert updated.active is False
    assert updated.success_ready is True
    assert updated.fallback_targets == []


def test_generate_report_contains_complete_bisect_tree_section(tmp_path):
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.workdirs = type("W", (), {"root": tmp_path})()
    builder.run_success = False
    builder.attempts_used = 3
    builder.stop_reason = "bisect_stagnated_requires_manual_review"
    builder.removed_mods = ["x.jar"]
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.last_ai_result = None
    builder.last_ai_manual_report = {}
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.attempt_traces = []
    builder.operations = []
    builder.detect_current_java_version = lambda: 21
    builder._attempt_trace_path = lambda attempt, stage: tmp_path / f"{attempt}_{stage}.json"
    builder._format_bisect_tree_lines = ServerBuilder._format_bisect_tree_lines.__get__(builder, ServerBuilder)
    builder.bisect_session = BisectSession(
        final_suspects=["b.jar", "c.jar"],
        pending_group=["b.jar", "c.jar"],
        next_allowed_requests=["continue_failed_group"],
        stagnant_rounds=1,
        rounds=[
            type(
                "Round",
                (),
                {
                    "round_index": 1,
                    "bisect_mode": "initial",
                    "tested_side": "keep",
                    "result": "pass",
                    "startup_success": True,
                    "requested_targets": ["a.jar", "b.jar", "c.jar", "d.jar"],
                    "kept_group": ["a.jar", "b.jar"],
                    "tested_group": ["c.jar", "d.jar"],
                    "moved_mods": [],
                    "continuation_targets": [],
                    "pending_other_group": ["c.jar", "d.jar"],
                    "next_allowed_requests": ["switch_group"],
                    "fallback_targets": [],
                    "suspects_invalidated": False,
                    "failure_kind": "",
                    "failure_detail": "",
                    "notes": ["start_success=True"],
                },
            )(),
        ],
    )

    report_path = ServerBuilder.generate_report(builder)
    report_text = report_path and (tmp_path / "report.txt").read_text(encoding="utf-8")

    assert "完整 Bisect Tree:" in report_text
    assert "Round 1: mode=initial" in report_text
    assert 'session.final_suspects=["b.jar", "c.jar"]' in report_text


def test_format_bisect_tree_lines_accepts_legacy_dict_round_records():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None
    builder.bisect_session = {
        "active": True,
        "final_suspects": ["b.jar"],
        "pending_group": ["b.jar"],
        "next_allowed_requests": ["switch_group"],
        "rounds": [
            {
                "round_index": 1,
                "bisect_mode": "initial",
                "tested_side": "keep",
                "result": "pass",
                "startup_success": True,
                "requested_targets": ["a.jar", "b.jar"],
                "keep_group": ["a.jar"],
                "test_group": ["b.jar"],
                "moved_mods": [{"mod": "lib.jar", "from": "test", "to": "keep", "reason": "legacy"}],
                "pending_group": ["b.jar"],
                "next_allowed_requests": ["switch_group"],
                "notes": ["legacy_record"],
            }
        ],
    }

    lines = ServerBuilder._format_bisect_tree_lines(builder)

    assert any("Round 1: mode=initial" in line for line in lines)
    assert any('moved_mods=[{"mod": "lib.jar", "from": "test", "to": "keep", "reason": "legacy"}]' in line for line in lines)


def test_consume_bisect_targets_prefers_fallback_targets_after_suspects_invalidated():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.list_mods = lambda: ["a.jar", "b.jar", "c.jar", "d.jar"]
    builder._resolve_mod_names_to_installed = ServerBuilder._resolve_mod_names_to_installed.__get__(builder, ServerBuilder)
    builder._normalize_mod_token = ServerBuilder._normalize_mod_token.__get__(builder, ServerBuilder)
    builder.bisect_session = BisectSession(
        active=True,
        suspects_invalidated=True,
        fallback_targets=["a.jar", "b.jar", "c.jar", "d.jar"],
        next_allowed_requests=["initial"],
    )

    bisect_mode, suspects = ServerBuilder._consume_bisect_targets(
        builder,
        {"type": "bisect_mods", "bisect_mode": "initial", "targets": ["a.jar", "b.jar"]},
    )

    assert bisect_mode == "initial"
    assert suspects == ["a.jar", "b.jar", "c.jar", "d.jar"]


def test_coerce_bisect_session_normalizes_round_and_move_records():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder._log = lambda *_args, **_kwargs: None

    session = ServerBuilder._coerce_bisect_session(
        builder,
        {
            "active": True,
            "rounds": [
                {
                    "round_index": 2,
                    "keep_group": ["a.jar"],
                    "test_group": ["b.jar"],
                    "moved_mods": [{"mod_name": "lib.jar", "from_group": "test", "to_group": "keep", "reason": "probe"}],
                }
            ],
        },
    )

    assert isinstance(session, BisectSession)
    assert isinstance(session.rounds[0], BisectRoundRecord)
    assert isinstance(session.rounds[0].moved_mods[0], BisectMoveRecord)
    assert session.rounds[0].moved_mods[0].mod_name == "lib.jar"


def test_apply_actions_stops_after_bisect_stagnates_twice():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.operations = []
    builder.attempts_used = 2
    builder.stop_reason = ""
    builder.last_ai_manual_report = {}
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder._append_attempt_trace = lambda *args, **kwargs: None
    builder._log = lambda *_args, **_kwargs: None
    builder._has_pending_bisect_followup = lambda: True
    builder._assess_action_preflight = lambda action: ActionPreflight(
        action_type="bisect_mods",
        risk="medium",
        allowed=False,
        reason="duplicate_bisect_request_after_previous_round",
        details=["same targets"],
    )
    builder.bisect_session = BisectSession(active=True, stagnant_rounds=1)
    builder._log_bisect_event = ServerBuilder._log_bisect_event.__get__(builder, ServerBuilder)

    should_stop = ServerBuilder._apply_actions(
        builder,
        [{"type": "bisect_mods", "bisect_mode": "initial", "targets": ["a.jar", "b.jar"]}],
        attempt=2,
    )

    assert should_stop is True
    assert builder.stop_reason == "bisect_stagnated_requires_manual_review"
    assert builder.last_ai_manual_report["user_summary"]


def test_successful_start_with_pending_bisect_followup_triggers_success_ai_analysis_instead_of_final_success():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"max_attempts": 2, "start_timeout": 5})()})()
    builder.manifest = None
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.operations = []
    builder.removed_mods = []
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.attempts_used = 0
    builder.run_success = False
    builder.stop_reason = ""
    builder.last_bisect_feedback = {"next_allowed_requests": ["switch_group"]}
    builder.bisect_session = BisectSession(active=True, pending_group=["b.jar"], next_allowed_requests=["switch_group"])
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder.backup_mods = lambda _tag: None
    builder._ensure_server_meta_files = lambda: None
    builder.generate_report = lambda: "report"
    builder.package_server = lambda: "package"
    builder.list_mods = lambda: ["a.jar", "b.jar"]
    builder.list_current_installed_client_mods = lambda: []
    builder.get_system_memory = lambda: 16
    builder._summarize_ai_context = lambda context: context
    builder._append_attempt_trace = lambda *args, **kwargs: None
    builder.extract_relevant_log = lambda *_args, **_kwargs: {"log_tail": "", "crash_excerpt": "", "conflicts_or_exceptions": []}
    builder.start_server = lambda timeout=300: {"success": True, "success_source": "log_done", "stdout_tail": "Done", "stderr_tail": ""}
    builder.analyze_with_ai = lambda context: {
        "primary_issue": "mod_conflict",
        "confidence": 0.5,
        "actions": [
            {
                "type": "bisect_mods",
                "bisect_mode": "switch_group",
                "bisect_reason": "继续验证另一组",
            }
        ],
    }

    applied_actions: list[dict] = []

    def apply_actions(actions: list[dict], attempt: int = 0) -> bool:
        applied_actions.extend(actions)
        builder.bisect_session = BisectSession(active=False)
        return False

    builder._apply_actions = apply_actions

    success = False
    for i in range(1, builder.config.runtime.max_attempts + 1):
        builder.attempts_used = i
        start_res = builder.start_server(timeout=builder.config.runtime.start_timeout)
        if start_res["success"]:
            if builder._has_pending_bisect_followup():
                ai_context = builder._build_ai_context(start_res, {"log_tail": "", "crash_excerpt": "", "conflicts_or_exceptions": []})
                ai = builder.analyze_with_ai(ai_context)
                should_stop = builder._apply_actions(ai.get("actions", []), attempt=i)
                if should_stop:
                    break
                if builder._has_pending_bisect_followup():
                    continue
            success = True
            builder.stop_reason = "server_ready:log_done"
            break

    assert applied_actions[0]["bisect_mode"] == "switch_group"
    assert success is True
    assert builder.stop_reason == "server_ready:log_done"


def test_successful_start_with_invalidated_suspects_auto_resumes_full_bisect_without_ai():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"max_attempts": 2, "start_timeout": 5})()})()
    builder.manifest = None
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.operations = []
    builder.removed_mods = []
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.attempts_used = 0
    builder.run_success = False
    builder.stop_reason = ""
    builder.last_bisect_feedback = {"next_allowed_requests": ["initial"], "suspects_invalidated": True}
    builder.bisect_session = BisectSession(
        active=True,
        suspects_invalidated=True,
        fallback_targets=["a.jar", "b.jar", "c.jar", "d.jar"],
        next_allowed_requests=["initial"],
    )
    builder._log = lambda *_args, **_kwargs: None
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder.backup_mods = lambda _tag: None
    builder._ensure_server_meta_files = lambda: None
    builder.generate_report = lambda: "report"
    builder.package_server = lambda: "package"
    builder.list_mods = lambda: ["a.jar", "b.jar", "c.jar", "d.jar"]
    builder.list_current_installed_client_mods = lambda: []
    builder.get_system_memory = lambda: 16
    builder._summarize_ai_context = lambda context: context
    builder._append_attempt_trace = lambda *args, **kwargs: None
    builder.extract_relevant_log = lambda *_args, **_kwargs: {"log_tail": "", "crash_excerpt": "", "conflicts_or_exceptions": []}
    builder.start_server = lambda timeout=300: {"success": True, "success_source": "log_done", "stdout_tail": "Done", "stderr_tail": ""}
    builder.analyze_with_ai = lambda context: (_ for _ in ()).throw(AssertionError("should not call ai"))
    builder._has_pending_bisect_followup = ServerBuilder._has_pending_bisect_followup.__get__(builder, ServerBuilder)
    builder._build_ai_context = ServerBuilder._build_ai_context.__get__(builder, ServerBuilder)
    builder._should_auto_resume_full_bisect = ServerBuilder._should_auto_resume_full_bisect.__get__(builder, ServerBuilder)
    builder._build_auto_resume_bisect_action = ServerBuilder._build_auto_resume_bisect_action.__get__(builder, ServerBuilder)
    builder._coerce_bisect_session = ServerBuilder._coerce_bisect_session.__get__(builder, ServerBuilder)

    applied_actions: list[dict] = []

    def apply_actions(actions: list[dict], attempt: int = 0) -> bool:
        applied_actions.extend(actions)
        builder.bisect_session = BisectSession(active=False)
        return False

    builder._apply_actions = apply_actions

    success = False
    for i in range(1, builder.config.runtime.max_attempts + 1):
        builder.attempts_used = i
        start_res = builder.start_server(timeout=builder.config.runtime.start_timeout)
        if start_res["success"]:
            if builder._has_pending_bisect_followup():
                auto_resumed_bisect = False
                if builder._should_auto_resume_full_bisect():
                    should_stop = builder._apply_actions([builder._build_auto_resume_bisect_action()], attempt=i)
                    if should_stop:
                        break
                    auto_resumed_bisect = True
                    if builder._has_pending_bisect_followup():
                        continue
                if auto_resumed_bisect:
                    success = True
                    builder.stop_reason = "server_ready:log_done"
                    break
                ai_context = builder._build_ai_context(start_res, {"log_tail": "", "crash_excerpt": "", "conflicts_or_exceptions": []})
                ai = builder.analyze_with_ai(ai_context)
                should_stop = builder._apply_actions(ai.get("actions", []), attempt=i)
                if should_stop:
                    break
                if builder._has_pending_bisect_followup():
                    continue
            success = True
            builder.stop_reason = "server_ready:log_done"
            break

    assert applied_actions[0]["bisect_mode"] == "initial"
    assert applied_actions[0]["targets"] == ["a.jar", "b.jar", "c.jar", "d.jar"]
    assert applied_actions[0]["request_source"] == "system_auto_resume"
    assert success is True
    assert builder.stop_reason == "server_ready:log_done"


def test_remove_mods_preflight_allows_multiple_targets_within_safe_limit():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.bisect_session = None
    builder.current_java_version = 17
    builder.get_system_memory = lambda: 16
    builder._resolve_mod_names_to_installed = lambda names: [name for name in names if name in {"a.jar", "b.jar", "c.jar"}]

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {"type": "remove_mods", "targets": ["a.jar", "b.jar", "c.jar"]},
    )

    assert preflight.allowed is True
    assert preflight.reason == "resolved_low_volume_mod_removal"


def test_remove_mods_preflight_rejects_targets_above_safe_limit():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.bisect_session = None
    builder.current_java_version = 17
    builder.get_system_memory = lambda: 16
    builder._resolve_mod_names_to_installed = lambda names: list(names)

    preflight = ServerBuilder._assess_action_preflight(
        builder,
        {"type": "remove_mods", "targets": ["a.jar", "b.jar", "c.jar", "d.jar"]},
    )

    assert preflight.allowed is False
    assert preflight.reason == "too_many_mod_targets"


def test_failed_start_with_crash_detected_skips_recognition_fallback_and_runs_ai():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.config = type("Cfg", (), {"runtime": type("Runtime", (), {"max_attempts": 1, "start_timeout": 5})()})()
    builder.manifest = None
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.operations = []
    builder.removed_mods = []
    builder.known_deleted_client_mods = set()
    builder.deleted_mod_evidence = {}
    builder.attempts_used = 0
    builder.run_success = False
    builder.stop_reason = ""
    logs: list[tuple[str, str, str]] = []
    builder._log = lambda tag, message, level="INFO": logs.append((tag, level, message))
    builder._ai_debug = lambda *_args, **_kwargs: None
    builder.backup_mods = lambda _tag: None
    builder._ensure_server_meta_files = lambda: None
    builder.generate_report = lambda: "report"
    builder.package_server = lambda: "package"
    builder._summarize_ai_context = lambda context: context
    builder._append_attempt_trace = lambda *args, **kwargs: None
    builder._select_next_recognition_plan = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not select fallback"))
    builder._apply_actions = lambda actions, attempt=0: True
    builder.extract_relevant_log = lambda *_args, **_kwargs: {
        "log_tail": "",
        "crash_excerpt": "fml crash",
        "crash_mod_issue": "",
        "conflicts_or_exceptions": [],
    }
    builder._build_ai_context = lambda start_res, log_info: {"start_res": start_res, "log_info": log_info}
    builder.start_server = lambda timeout=300: {
        "success": False,
        "crash_detected": True,
        "stdout_tail": "",
        "stderr_tail": "fml crash",
        "log_path": "latest.log",
        "crash_dir": "crash-reports",
        "failure_signals": ["crash_report_created"],
    }

    ai_calls: list[dict] = []
    builder.analyze_with_ai = lambda context: ai_calls.append(context) or {
        "primary_issue": "mod_conflict",
        "confidence": 0.9,
        "actions": [{"type": "stop_and_report", "final_reason": "crash analyzed"}],
    }

    success = False
    for i in range(1, builder.config.runtime.max_attempts + 1):
        builder.attempts_used = i
        builder._log("install.attempt", f"启动尝试 {i}/{builder.config.runtime.max_attempts}")
        builder.backup_mods(f"attempt_{i}")
        start_res = builder.start_server(timeout=builder.config.runtime.start_timeout)
        if start_res["success"]:
            success = True
            break
        log_info = builder.extract_relevant_log(str(start_res["log_path"]), str(start_res["crash_dir"]))
        ai_context = builder._build_ai_context(start_res, log_info)
        next_plan = None
        if start_res.get("crash_detected"):
            builder._log("install.ai", "检测到 crash 证据，跳过 runtime recognition fallback，直接进入 AI 分析")
        else:
            next_plan = builder._select_next_recognition_plan(start_res, log_info)
        if next_plan:
            raise AssertionError("recognition fallback should be skipped")
        ai = builder.analyze_with_ai(ai_context)
        should_stop = builder._apply_actions(ai.get("actions", []), attempt=i)
        if should_stop:
            builder.stop_reason = "crash analyzed"
            break

    assert success is False
    assert len(ai_calls) == 1
    assert ai_calls[0]["start_res"]["crash_detected"] is True
    assert any("跳过 runtime recognition fallback" in message for tag, _level, message in logs if tag == "install.ai")


def test_backup_mods_skips_repeated_snapshot_when_mods_unchanged(tmp_path: Path):
    builder = ServerBuilder.__new__(ServerBuilder)
    mods_dir = tmp_path / "server" / "mods"
    backups_dir = tmp_path / "backups"
    mods_dir.mkdir(parents=True)
    backups_dir.mkdir(parents=True)
    (mods_dir / "a.jar").write_text("a", encoding="utf-8")
    (mods_dir / "b.jar").write_text("b", encoding="utf-8")

    builder.workdirs = type("WorkDirs", (), {"server": tmp_path / "server", "backups": backups_dir})()
    builder.operations = []
    builder._mods_backup_signatures = {}
    builder.backup_mods = ServerBuilder.backup_mods.__get__(builder, ServerBuilder)

    builder.backup_mods("attempt_1")
    first_mtime = (backups_dir / "mods_attempt_1").stat().st_mtime_ns

    builder.backup_mods("attempt_1")
    second_mtime = (backups_dir / "mods_attempt_1").stat().st_mtime_ns

    assert first_mtime == second_mtime
    assert builder.operations == ["backup_mods:attempt_1", "backup_mods_skip_unchanged:attempt_1"]


def test_backup_mods_recreates_snapshot_when_mods_changed(tmp_path: Path):
    builder = ServerBuilder.__new__(ServerBuilder)
    mods_dir = tmp_path / "server" / "mods"
    backups_dir = tmp_path / "backups"
    mods_dir.mkdir(parents=True)
    backups_dir.mkdir(parents=True)
    (mods_dir / "a.jar").write_text("a", encoding="utf-8")

    builder.workdirs = type("WorkDirs", (), {"server": tmp_path / "server", "backups": backups_dir})()
    builder.operations = []
    builder._mods_backup_signatures = {}
    builder.backup_mods = ServerBuilder.backup_mods.__get__(builder, ServerBuilder)

    builder.backup_mods("attempt_1")
    (mods_dir / "b.jar").write_text("b", encoding="utf-8")

    builder.backup_mods("attempt_1")

    backup_files = sorted(path.name for path in (backups_dir / "mods_attempt_1").iterdir())
    assert backup_files == ["a.jar", "b.jar"]
    assert builder.operations == ["backup_mods:attempt_1", "backup_mods:attempt_1"]


def test_mark_bisect_success_ready_clears_followups_and_sets_guard_state():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.bisect_session = BisectSession(
        active=True,
        pending_group=["b.jar"],
        next_allowed_requests=["switch_group"],
        fallback_targets=["a.jar", "b.jar"],
    )
    builder._coerce_bisect_session = ServerBuilder._coerce_bisect_session.__get__(builder, ServerBuilder)

    ServerBuilder._mark_bisect_success_ready(builder, "bisect_converged")

    assert builder.bisect_session.active is False
    assert builder.bisect_session.success_ready is True
    assert builder.bisect_session.success_guard_reason == "bisect_converged"
    assert builder.bisect_session.pending_group == []
    assert builder.bisect_session.next_allowed_requests == []


def test_record_success_guard_observation_counts_repeated_client_mod_issue():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.bisect_session = BisectSession(success_ready=True)
    builder._coerce_bisect_session = ServerBuilder._coerce_bisect_session.__get__(builder, ServerBuilder)

    first = ServerBuilder._record_success_guard_observation(builder, "client_mod", 0.91)
    second = ServerBuilder._record_success_guard_observation(builder, "client_mod", 0.88)

    assert first == 1
    assert second == 2
    assert builder.bisect_session.consecutive_same_issue_on_success == 2
    assert len(builder.bisect_session.success_guard_history) == 2


def test_should_accept_success_after_start_blocks_when_bisect_followup_pending():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.bisect_session = BisectSession(active=True, pending_group=["b.jar"], next_allowed_requests=["switch_group"])
    builder._coerce_bisect_session = ServerBuilder._coerce_bisect_session.__get__(builder, ServerBuilder)
    builder._has_pending_bisect_followup = ServerBuilder._has_pending_bisect_followup.__get__(builder, ServerBuilder)

    accepted, reason = ServerBuilder._should_accept_success_after_start(builder, {"success_source": "log_done"})

    assert accepted is False
    assert reason == "bisect_followup_pending"


def test_build_prompt_mentions_success_guard_and_stable_split_strategy():
    builder = ServerBuilder.__new__(ServerBuilder)
    service = BuilderAIService(builder)

    prompt = service.build_prompt(
        {
            "bisect_active": True,
            "bisect_phase": "fallback",
            "bisect_next_allowed_requests": ["switch_group"],
            "bisect_success_ready": True,
            "bisect_consecutive_same_issue_on_success": 1,
        }
    )

    assert "按文件名稳定排序后平分为 keep_group 与 test_group" in prompt
    assert "成功态防回归规则" in prompt
    assert "consecutive_same_issue_on_success" in prompt

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import psutil

from mc_auto_server_builder.ai import BuilderAIService
from mc_auto_server_builder.builder import ServerBuilder
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
from mc_auto_server_builder.recognition import RecognitionFallbackPlan, choose_latest_lts_java_version


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
    builder.last_rollback_remove_mods = {
        "triggered": True,
        "snapshot_tag": "attempt_1_action_1",
        "crash_reports_changed_since_last_context": False,
    }

    preflight = ServerBuilder._assess_action_preflight(builder, {"type": "restore_mods_and_continue"})

    assert preflight.allowed is False
    assert preflight.reason == "crash_reports_not_changed_after_rollback_remove_mods"


def test_execute_restore_mods_and_continue_rolls_back_snapshot():
    builder = ServerBuilder.__new__(ServerBuilder)
    builder.last_rollback_remove_mods = {
        "triggered": True,
        "snapshot_tag": "attempt_1_action_1",
        "removed_targets": ["bad.jar"],
        "crash_reports_changed_since_last_context": True,
    }
    builder.rollback_mods = lambda tag: builder.__dict__.setdefault("rollback_calls", []).append(tag)
    builder.operations = []
    builder.jvm_xmx = "4G"
    builder.jvm_xms = "4G"
    builder.extra_jvm_flags = []
    builder.current_java_version = 21
    builder.current_java_bin = None

    stop, execution, rollback = ServerBuilder._execute_action_with_safeguards(
        builder,
        1,
        {"type": "restore_mods_and_continue"},
        ActionPreflight(action_type="restore_mods_and_continue", risk="low", allowed=True, reason="rollback_restore_allowed"),
        "attempt_2_action_1",
    )

    assert stop is False
    assert rollback is None
    assert execution["status"] == "applied"
    assert execution["restored_snapshot_tag"] == "attempt_1_action_1"
    assert builder.rollback_calls == ["attempt_1_action_1"]
    assert "restore_mods_and_continue:attempt_1_action_1" in builder.operations


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
    builder.operations = ["op1"]
    builder._build_recognition_summary = ServerBuilder._build_recognition_summary.__get__(builder, ServerBuilder)
    builder._serialize_detection_candidates = ServerBuilder._serialize_detection_candidates.__get__(builder, ServerBuilder)
    builder.detect_current_java_version = lambda: 21

    payload = ServerBuilder._build_meta_payload(builder)

    assert payload["pack_source"]["input_type"] == "local_zip"
    assert payload["manifest_summary"]["pack_name"] == "Example Pack"
    assert payload["recognition_result"]["active_loader"] == "forge"
    assert payload["java"]["selected_version"] == 21
    assert payload["deleted_mods"]["removed_mods"] == ["bad.jar"]


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

    out = ServerBuilder.package_server(builder)

    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        assert "build_meta.json" in names
        payload = json.loads(zf.read("build_meta.json").decode("utf-8"))
        assert payload["manifest_summary"]["loader"] == "forge"
        assert "server.jar" in names
        assert "java_bins/java" in names


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

    report_path = ServerBuilder.generate_report(builder)
    report_text = (tmp_path / "report.txt").read_text(encoding="utf-8")

    assert report_path
    assert "删除 mod 来源分层统计:" in report_text
    assert '"builtin_rule": ["builtin_rule:client_only"]' in report_text


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

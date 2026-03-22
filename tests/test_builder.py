from __future__ import annotations

from mc_auto_server_builder.ai import BuilderAIService
from mc_auto_server_builder.builder import ServerBuilder
from mc_auto_server_builder.models import ActionPreflight, AIResult, BisectMoveRecord, BisectRoundRecord, BisectSession


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
    assert execution["validation_start_performed"] is True
    assert execution["validation_success"] is False
    assert rollback is not None
    assert rollback["performed"] is True
    assert state["mods"] == ["bad.jar", "good.jar"]


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

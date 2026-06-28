from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ai import BuilderAIService


def normal_failure_schema_example(service: BuilderAIService) -> dict[str, object]:
    return {
        "thought_chain": ["最多 8 条简短推理"],
        "final_output": {
            "primary_issue": (
                "client_mod|memory_allocation|memory_oom|java_version_mismatch|mod_conflict|missing_dependency|config_error|pack_recognition_error|loader_misclassification|version_misclassification|start_command_misclassification|other"
            ),
            "confidence": 0.0,
            "reason": "技术原因摘要",
            "input_summary": "输入信息摘要",
            "user_summary": "给用户看的结论",
            "hit_deleted_mods": ["..."],
            "dependency_chains": [["dependent", "...", "deleted_mod"]],
            "deletion_rationale": ["..."],
            "conflicts_or_exceptions": ["..."],
            "evidence": ["关键证据"],
            "suggested_manual_steps": ["人工修复步骤"],
            "actions": [
                {"type": "remove_mods", "targets": ["modA.jar"], "rollback_on_failure": True},
                {
                    "type": "continue_after_restore_mods",
                    "reason": "专项删除验证确认故障形态变化，需要恢复到删除后的工作集并继续一次常规分析",
                },
                {
                    "type": "bisect_mods",
                    "bisect_mode": "initial",
                    "targets": ["modA.jar", "modB.jar"],
                    "bisect_reason": "日志无法唯一命中单个 mod，但这两个 mod 最可疑，申请系统先对最小 suspects 集合做受控二分",
                    "max_rounds": 1,
                },
                {
                    "type": "bisect_mods",
                    "bisect_mode": "switch_group",
                    "bisect_reason": "当前组已启动成功，申请系统切换验证另一组",
                },
                {
                    "type": "bisect_mods",
                    "bisect_mode": "continue_failed_group",
                    "bisect_reason": "失败组仍包含多个嫌疑 mod，申请继续稳定二分",
                },
                {"type": "move_bisect_mods", "targets": ["libX.jar"], "reason": "当前测试组缺少前置依赖，申请从另一组临时迁移"},
                {"type": "adjust_memory", "xmx": "6G", "xms": "4G"},
                {"type": "change_java", "version": 21},
                {
                    "type": "switch_recognition_candidate",
                    "loader": "forge",
                    "loader_version": "1.20.1-47.2.0",
                    "mc_version": "1.20.1",
                    "start_mode": "argsfile",
                    "build": "47.2.0",
                    "reason": "日志反证当前识别错误",
                },
                {
                    "type": "report_manual_fix",
                    "final_reason": "崩溃主因",
                    "reason": "为什么无法自动修复",
                    "manual_steps": ["步骤1"],
                    "evidence": ["证据1"],
                },
                {"type": "stop_and_report", "final_reason": "证据不足，保守停止"},
            ],
        },
    }


def success_guard_schema_example(service: BuilderAIService) -> dict[str, object]:
    return {
        "thought_chain": ["最多 6 条简短推理"],
        "final_output": {
            "primary_issue": "client_mod|mod_conflict|missing_dependency|other",
            "confidence": 0.0,
            "reason": "成功态风险摘要",
            "input_summary": "成功态输入摘要",
            "user_summary": "给用户看的结论",
            "evidence": ["关键证据"],
            "suggested_manual_steps": ["人工修复步骤"],
            "actions": [
                {"type": "remove_mods", "targets": ["modA.jar"], "rollback_on_failure": True},
                {
                    "type": "bisect_mods",
                    "bisect_mode": "switch_group",
                    "bisect_reason": "当前组已启动成功，申请系统切换验证另一组",
                },
                {"type": "move_bisect_mods", "targets": ["libX.jar"], "reason": "成功组缺少前置依赖，申请迁移依赖"},
                {
                    "type": "report_manual_fix",
                    "final_reason": "成功态仍存在残余风险，需要人工确认",
                    "manual_steps": ["步骤1"],
                    "evidence": ["证据1"],
                },
                {"type": "stop_and_report", "final_reason": "成功态证据不足，保守停止"},
            ],
        },
    }


def remove_validation_schema_example(service: BuilderAIService) -> dict[str, object]:
    return {
        "thought_chain": ["最多 6 条简短推理"],
        "final_output": {
            "primary_issue": "mod_conflict|missing_dependency|client_mod|other",
            "confidence": 0.0,
            "reason": "删除验证结论",
            "input_summary": "验证输入摘要",
            "user_summary": "给用户看的结论",
            "evidence": ["关键证据"],
            "suggested_manual_steps": ["人工步骤"],
            "actions": [
                {
                    "type": "continue_after_restore_mods",
                    "reason": "删除后故障形态变化，说明这次删除命中了问题方向；请恢复到删除后的工作集并继续一次后续动作",
                },
                {"type": "report_manual_fix", "final_reason": "需要人工处理", "manual_steps": ["步骤1"], "evidence": ["证据1"]},
                {"type": "stop_and_report", "final_reason": "删除验证未提供可继续的新信息"},
            ],
        },
    }


def build_structured_output_schema(service: BuilderAIService, allowed_action_types: list[str]) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "thought_chain": {"type": "array", "items": {"type": "string"}},
            "final_output": {
                "type": "object",
                "additionalProperties": True,
                "properties": {
                    "primary_issue": {"type": "string"},
                    "confidence": {"type": "number"},
                    "reason": {"type": "string"},
                    "input_summary": {"type": "string"},
                    "user_summary": {"type": "string"},
                    "hit_deleted_mods": {"type": "array", "items": {"type": "string"}},
                    "dependency_chains": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
                    "deletion_rationale": {"type": "array", "items": {"type": "string"}},
                    "conflicts_or_exceptions": {"type": "array", "items": {"type": "string"}},
                    "suggested_manual_steps": {"type": "array", "items": {"type": "string"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": True,
                            "properties": {
                                "type": {"type": "string", "enum": allowed_action_types},
                                "targets": {"type": "array", "items": {"type": "string"}},
                                "rollback_on_failure": {"type": "boolean"},
                                "xmx": {"type": "string"},
                                "xms": {"type": "string"},
                                "version": {"type": "integer"},
                                "reason": {"type": "string"},
                                "final_reason": {"type": "string"},
                                "manual_steps": {"type": "array", "items": {"type": "string"}},
                                "evidence": {"type": "array", "items": {"type": "string"}},
                                "bisect_mode": {"type": "string"},
                                "bisect_reason": {"type": "string"},
                                "move_candidates": {"type": "array", "items": {"type": "string"}},
                                "max_rounds": {"type": "integer"},
                                "allow_dependency_moves": {"type": "boolean"},
                                "loader": {"type": "string"},
                                "loader_version": {"type": "string"},
                                "mc_version": {"type": "string"},
                                "start_mode": {"type": "string"},
                                "build": {"type": "string"},
                            },
                            "required": ["type"],
                        },
                    },
                },
                "required": ["primary_issue", "confidence", "reason", "actions"],
            },
        },
        "required": ["final_output"],
    }


def build_response_format(service: BuilderAIService, name: str, allowed_action_types: list[str]) -> dict[str, object]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": name,
            "strict": False,
            "schema": service._build_structured_output_schema(allowed_action_types),
        },
    }


def build_json_repair_prompt(service: BuilderAIService, raw_text: str, schema_example: dict[str, object]) -> str:
    return "".join(
        [
            "你是一个 JSON 修复器。\n",
            "不要重新分析 Minecraft 问题，不要补充新结论，只把已有输出修复成一个严格 JSON 对象。\n",
            "要求：1. 只能输出 JSON；2. 保留原语义；3. 若某字段缺失，可给出最保守的空值或默认值；4. 不要输出 markdown 代码块。\n",
            f"参考结构示例: {json.dumps(schema_example, ensure_ascii=False)}\n",
            f"待修复文本: {service._truncate_debug_text(raw_text, 12000)}",
        ]
    )


def build_remove_validation_prompt(service: BuilderAIService, context: dict) -> str:
    schema = service._remove_validation_schema_example()
    return "".join(
        [
            "你是 Minecraft 服务器自动修复流程中的删除验证裁决器。\n",
            (
                "你的任务不是做完整日志分析，而是只根据一次 remove_mods + rollback_on_failure 的验证结果，"
                "判断这次删除是否命中了问题方向，以及系统是否应该在下一轮恢复到删除后的工作集后继续执行一次后续动作。\n"
            ),
            "优先参考 deterministic_tools 中的 crash_report_analysis 与 dependency_graph，再决定是否继续。\n",
            "硬规则：1. 只能输出 continue_after_restore_mods、report_manual_fix、stop_and_report 三类动作。",
            (
                "2. 当 validation_target.removed_targets 删除后，"
                "failure_comparison.problem_changed=true，且差异证据足以说明故障形态改变时，"
                "优先输出 continue_after_restore_mods。"
            ),
            (
                "3. continue_after_restore_mods 的语义是：上一轮结束时系统已自动恢复删前基线；"
                "当前轮再恢复到删除后的工作集，并保留本轮删除验证日志与差异证据，再进入下一次常规分析。"
            ),
            "4. 若故障没有变化，或变化不足以支持继续自动动作，禁止输出 continue_after_restore_mods。",
            "5. 不要输出 remove_mods、bisect_mods、adjust_memory、change_java 等常规动作；那些动作会在下一阶段由常规分析器决定。\n",
            "输出必须是严格 JSON，不要包含 markdown 代码块，不要输出额外解释。\n",
            f"结构化上下文: {json.dumps(context, ensure_ascii=False)[:8000]}\n",
            f"返回 JSON Schema 示例: {json.dumps(schema, ensure_ascii=False)}",
        ]
    )


def build_success_guard_prompt(service: BuilderAIService, context: dict) -> str:
    schema = service._success_guard_schema_example()
    return "".join(
        [
            "你是 Minecraft 服务器自动修复流程中的成功态专项分析器。\n",
            (
                "当前服务器已经出现启动成功信号，但系统仍在 success guard / bisect followup 阶段，"
                "需要判断是否还存在残余客户端模组或分组验证风险。\n"
            ),
            "优先参考 deterministic_tools 中的 start_command_check、dependency_graph、mod_metadata_summary。\n",
            "硬规则：1. 只允许输出 remove_mods、bisect_mods、move_bisect_mods、report_manual_fix、stop_and_report。",
            "2. 禁止输出 adjust_memory、change_java、switch_recognition_candidate、continue_after_restore_mods。",
            "3. 若 bisect_state.active=true，必须优先遵循 next_allowed_requests、last_feedback、fallback_targets，不能自由重猜分组。",
            "4. 若证据只能支持剩余风险提示，不能安全自动动作，则优先 report_manual_fix，而不是重复成功态回归。\n",
            "动作优先级：1. 成功态若能唯一锁定残余客户端模组，优先 remove_mods。",
            (
                "2. 若当前只是二分流程尚未完成，优先 bisect_mods 或 move_bisect_mods，"
                "保持与 pending_group、continuation_targets、tested_side 一致。"
            ),
            "3. 若 success_guard_history 已连续出现同类风险而证据仍不收敛，优先 report_manual_fix。",
            "4. 只有当证据不足以支持任何安全动作时，才允许 stop_and_report。\n",
            "输出必须是严格 JSON，不要包含 markdown 代码块，不要输出额外解释。\n",
            f"结构化上下文: {json.dumps(context, ensure_ascii=False)[:12000]}\n",
            f"返回 JSON Schema 示例: {json.dumps(schema, ensure_ascii=False)}",
        ]
    )


def build_prompt(service: BuilderAIService, context: dict) -> str:
    schema = service._normal_failure_schema_example()
    return "".join(
        [
            "你是一个专业的Minecraft服务器部署与优化助手。\n",
            "任务目标：先识别主因，再选择最安全、最可执行的动作。"
            "证据优先级：异常堆栈/错误关键字 > 已删除客户端mod依赖链 > 最近自动操作 > 其他上下文。\n",
            "优先参考 deterministic_tools 中的 crash_report_analysis、dependency_graph、start_command_check；"
            "这些是系统先做过的确定性检查。\n",
            "硬规则：1. 若某个 mod 依赖任何已知且已删除的客户端 mod，则该 mod 必须判定为 remove_mods。"
            "2. 若证据只能唯一锁定 1 个候选，则 remove_mods 只提交这 1 个最有把握的 mod。"
            "但若证据已明确表明多个 mod 都是客户端专用 mod，允许一次提交多个 remove_mods targets；"
            "不过总数绝不能超过系统源码中的安全上限（当前为 3 个）。"
            "3. 对 remove_mods，若你希望系统在删除后做一次启动验证并在失败时自动回滚，"
            "则显式输出 rollback_on_failure=true。"
            "4. continue_after_restore_mods 只应由专项删除验证阶段产出；常规分析阶段不要主动把它当作候选策略。"
            "5. 若单个 remove_mods 候选执行后仍不能解决问题，且证据不再足以唯一锁定下一个单一 mod，"
            "则优先回到删除前基线并改用受控二分，而不是继续盲目累计删除。"
            "6. 输出 bisect_mods 时，bisect_mode 只能是 initial|switch_group|continue_failed_group，"
            "且 AI 不得指定 keep_group 或 test_group。"
            "7. 若最近一次阻止原因为 duplicate_bisect_stage_request 或 "
            "duplicate_bisect_request_after_previous_round，则禁止再次输出任何 bisect_mods，"
            "必须改为 report_manual_fix、remove_mods、adjust_memory、change_java 或 stop_and_report。\n",
            "二分状态机：1. 若 bisect_state.active=true，优先消费 last_feedback、"
            "next_allowed_requests、fallback_targets，不得自由重猜 suspects。"
            "2. 系统分组方式固定为：按文件名稳定排序后平分为 keep_group 与 test_group；"
            "AI 只能请求 suspects，不能手工指定分组。"
            "3. 只有系统明确允许 switch_group 时，才能申请 switch_group；"
            "只有系统明确允许 continue_failed_group 时，才能申请 continue_failed_group。"
            "4. 若 suspects_invalidated=true 且 next_allowed_requests 包含 initial，"
            "则这表示系统已进入新的 fallback initial phase；此时 initial 只能使用 fallback_targets，"
            "不能复用旧的最小猜测子集，也不应视为重复请求。"
            "5. 仅当 bisect_state.active=true 且 next_allowed_requests 为空时，才不得输出 bisect_mods；"
            "若 bisect_state.active=false，且仍有至少 2 个可疑 mod，则允许发起 initial。"
            "6. 若上一轮 keep/test 分组与结果已明确，你的 actions 必须与 tested_side、"
            "pending_group、continuation_targets 保持一致。\n",
            "成功态防回归规则：1. 普通安装可由 log_done 等信号判成功，但只要 bisect_state.active=true，"
            "就绝不能把这次启动视为最终成功。2. 若 bisect_state.success_ready=true，说明系统已收敛完二分，"
            "AI 应避免再发起新的大范围回归动作。3. 若 bisect_state.consecutive_same_issue_on_success>=1，"
            "表示系统已经在成功态连续观察到同类问题；此时必须更保守，优先 remove_mods 或 report_manual_fix，"
            "不要重复输出等价的 client_mod 二分。4. 若 success_guard_history 已显示连续同类 client_mod 判断，"
            "而证据仍不能收敛到新动作，则必须 report_manual_fix，禁止无意义循环。\n",
            "动作优先级：1. 证据已唯一命中单个 mod 或明确依赖链时，优先 remove_mods；"
            "若只是多个可疑候选，则仍应只提交最有把握的那 1 个。"
            "只有在证据明确证明多个 mod 都属于客户端 mod 时，才允许一次提交多个 targets，且最多 3 个。"
            "2. 若专项删除验证已经确认问题形态变化，系统会单独处理 continue_after_restore_mods；常规分析阶段无需重复判断该动作。"
            "3. 若该单删动作只是高置信试探、删除后可能需要立即验证是否误删，"
            "优先为 remove_mods 增加 rollback_on_failure=true。"
            "4. 若多个候选都可疑但没有足够把握安全单删，或单删后问题依旧且需要重新缩小范围，"
            "则优先回滚该删除思路并给出最小 suspects 集合申请 bisect_mods。"
            "5. 只有在证据明确表明当前测试组缺少必要依赖，且该依赖位于另一组时，"
            "才可追加 move_bisect_mods。6. 若系统连续无进展或无法安全自动修复，但能说明原因与修复步骤，"
            "必须输出 report_manual_fix。7. 只有当无法唯一命中单一 mod、无法构造至少 2 个 mod 的 suspects、"
            "系统也未开放任何续轮二分动作、且现有证据不足以支持 remove_mods、adjust_memory、change_java "
            "或 report_manual_fix 时，才允许 stop_and_report。\n",
            "schema补充：move_bisect_mods 只能跟在一个已准备好的 bisect_mods 之后，"
            "targets 表示要从另一组临时迁移到当前测试组的少量 mod。\n",
            "输出必须是严格 JSON，不要包含 markdown 代码块，不要输出额外解释。\n",
            f"结构化上下文: {json.dumps(context, ensure_ascii=False)[:12000]}\n",
            f"返回 JSON Schema 示例: {json.dumps(schema, ensure_ascii=False)}",
        ]
    )

from __future__ import annotations

import json
import re
import time
import traceback
from dataclasses import asdict, fields, is_dataclass
from typing import TYPE_CHECKING

import requests

from .models import AIAction, AIResult

if TYPE_CHECKING:
    from .builder import ServerBuilder


class BuilderAIService:
    def __init__(self, builder: ServerBuilder):
        self.builder = builder

    def _ai_debug_enabled(self) -> bool:
        return bool(self.builder.config.ai.enabled and self.builder.config.ai.debug)

    def _ai_debug(self, message: str) -> None:
        if self._ai_debug_enabled():
            noisy_prefixes = (
                "response.parse.stage=",
                "response.raw",
                "response.parse failed",
                "openai.retry",
                "ollama.retry",
                "openai.request",
                "openai.response",
                "normalize.actions[",
                "normalize.confidence.invalid",
            )
            if message.startswith(noisy_prefixes):
                return
            self.builder._log("install.ai.debug", message, level="DEBUG")

    def _truncate_debug_text(self, value: object, limit: int = 1000) -> str:
        text = str(value)
        if len(text) <= limit:
            return text
        return f"{text[:limit]}...<truncated:{len(text) - limit}>"

    def _serialize_ai_action(self, action: object) -> dict:
        if isinstance(action, dict):
            return dict(action)

        if is_dataclass(action):
            return asdict(action)

        if hasattr(action, "model_dump") and callable(getattr(action, "model_dump")):
            dumped = action.model_dump()  # type: ignore[attr-defined]
            return dumped if isinstance(dumped, dict) else {"type": str(action)}

        if hasattr(action, "dict") and callable(getattr(action, "dict")):
            dumped = action.dict()  # type: ignore[attr-defined]
            return dumped if isinstance(dumped, dict) else {"type": str(action)}

        if isinstance(action, AIAction):
            return {f.name: getattr(action, f.name) for f in fields(AIAction)}

        mapped: dict[str, object] = {}
        for key in ("type", "targets", "xmx", "xms", "version", "reason", "final_reason"):
            if hasattr(action, key):
                mapped[key] = getattr(action, key)
        if mapped:
            return mapped

        return {"type": str(action)}

    def _extract_json_object(self, text: str) -> dict | None:
        payload = (text or "").strip()
        if not payload:
            return None

        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                self._ai_debug("response.parse.stage=full_json status=ok")
                return data
        except json.JSONDecodeError:
            self._ai_debug("response.parse.stage=full_json status=miss")

        fence = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", payload, flags=re.IGNORECASE)
        if fence:
            block = fence.group(1)
            try:
                data = json.loads(block)
                if isinstance(data, dict):
                    self._ai_debug("response.parse.stage=fenced_json status=ok")
                    return data
            except json.JSONDecodeError:
                self._ai_debug("response.parse.stage=fenced_json status=miss")

        decoder = json.JSONDecoder()
        search_pos = 0
        while True:
            start = payload.find("{", search_pos)
            if start == -1:
                break
            try:
                obj, end = decoder.raw_decode(payload, start)
                if isinstance(obj, dict):
                    self._ai_debug(f"response.parse.stage=raw_decode status=ok start={start} end={end}")
                    return obj
                self._ai_debug(f"response.parse.stage=raw_decode status=skip_non_dict start={start} type={type(obj).__name__}")
                search_pos = max(start + 1, end)
            except json.JSONDecodeError:
                search_pos = start + 1

        start = payload.find("{")
        end = payload.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = payload[start : end + 1]
            try:
                data = json.loads(snippet)
                if isinstance(data, dict):
                    self._ai_debug("response.parse.stage=span_snippet status=ok")
                    return data
            except json.JSONDecodeError:
                self._ai_debug("response.parse.stage=span_snippet status=miss")
                return None
        return None

    def _safe_ai_result(self, reason: str, confidence: float = 0.1) -> AIResult:
        return AIResult(
            primary_issue="other",
            confidence=max(0.0, min(1.0, confidence)),
            reason=reason,
            actions=[],
            thought_chain=[],
            input_summary="",
            hit_deleted_mods=[],
            dependency_chains=[],
            deletion_rationale=[],
            conflicts_or_exceptions=[],
            user_summary="",
            suggested_manual_steps=[],
            evidence=[],
        )

    def _normalize_text_list(self, value: object, limit: int = 50) -> list[str]:
        return [str(x).strip() for x in (value if isinstance(value, list) else []) if str(x).strip()][:limit]

    def _normalize_ai_result(self, data: dict) -> AIResult:
        allowed_issue = {
            "client_mod",
            "memory_allocation",
            "memory_oom",
            "java_version_mismatch",
            "mod_conflict",
            "missing_dependency",
            "config_error",
            "pack_recognition_error",
            "loader_misclassification",
            "version_misclassification",
            "start_command_misclassification",
            "other",
        }
        allowed_action = {
            "remove_mods",
            "restore_mods_and_continue",
            "adjust_memory",
            "change_java",
            "stop_and_report",
            "report_manual_fix",
            "bisect_mods",
            "move_bisect_mods",
            "switch_recognition_candidate",
        }

        final_output = data.get("final_output")
        final_output = final_output if isinstance(final_output, dict) else {}

        def _pick(key: str, default: object) -> object:
            if key in data:
                return data.get(key, default)
            return final_output.get(key, default)

        issue = str(_pick("primary_issue", "other") or "other").strip()
        if issue not in allowed_issue:
            self._ai_debug(f"normalize.primary_issue.invalid value={issue!r}, fallback='other'")
            issue = "other"

        confidence_raw = _pick("confidence", 0.0)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            self._ai_debug(f"normalize.confidence.invalid value={confidence_raw!r}, fallback=0.0")
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        reason = str(_pick("reason", "") or "").strip() or "AI 返回了空原因"
        thought_chain = self._normalize_text_list(_pick("thought_chain", []), limit=8)
        input_summary = str(_pick("input_summary", "") or "").strip()
        user_summary = str(_pick("user_summary", "") or "").strip()
        hit_deleted_mods = self._normalize_text_list(_pick("hit_deleted_mods", []), limit=50)

        raw_dependency_chains = _pick("dependency_chains", [])
        dependency_chains: list[list[str]] = []
        if isinstance(raw_dependency_chains, list):
            for item in raw_dependency_chains[:50]:
                if isinstance(item, list):
                    chain = [str(x).strip() for x in item if str(x).strip()]
                elif isinstance(item, str):
                    chain = [x.strip() for x in re.split(r"\s*(?:->|=>|＞|→)\s*", item) if x.strip()]
                else:
                    chain = []
                if len(chain) >= 2:
                    dependency_chains.append(chain)

        deletion_rationale = self._normalize_text_list(_pick("deletion_rationale", []), limit=50)
        conflicts_or_exceptions = self._normalize_text_list(_pick("conflicts_or_exceptions", []), limit=50)
        suggested_manual_steps = self._normalize_text_list(_pick("suggested_manual_steps", []), limit=20)
        evidence = self._normalize_text_list(_pick("evidence", []), limit=20)

        action_models: list[AIAction] = []
        raw_actions = _pick("actions", []) or []
        if not isinstance(raw_actions, list):
            self._ai_debug(f"normalize.actions.invalid_type type={type(raw_actions).__name__}, fallback=[]")
            raw_actions = []
        for idx, item in enumerate(raw_actions[:2], start=1):
            if not isinstance(item, dict):
                self._ai_debug(f"normalize.actions[{idx}].drop reason=not_dict type={type(item).__name__}")
                continue
            action_type = str(item.get("type", "") or "").strip()
            if action_type not in allowed_action:
                self._ai_debug(f"normalize.actions[{idx}].drop reason=unknown_type type={action_type!r}")
                continue
            normalized_item = dict(item)
            if action_type == "report_manual_fix":
                normalized_item.setdefault("final_reason", normalized_item.get("final_reason") or reason)
                normalized_item["manual_steps"] = self._normalize_text_list(
                    normalized_item.get("manual_steps") or suggested_manual_steps,
                    limit=20,
                )
                normalized_item["evidence"] = self._normalize_text_list(
                    normalized_item.get("evidence") or evidence or conflicts_or_exceptions,
                    limit=20,
                )
            try:
                action_models.append(AIAction(**normalized_item))
                self._ai_debug(f"normalize.actions[{idx}].accept type={action_type!r}")
            except TypeError:
                self._ai_debug(f"normalize.actions[{idx}].fallback reason=payload_mismatch type={action_type!r}")
                action_models.append(AIAction(type=action_type))

        if not action_models:
            if suggested_manual_steps or evidence or user_summary:
                self._ai_debug("normalize.actions.empty -> inject report_manual_fix")
                action_models = [
                    AIAction(
                        type="report_manual_fix",
                        reason=reason,
                        final_reason=user_summary or reason,
                        manual_steps=suggested_manual_steps,
                        evidence=evidence or conflicts_or_exceptions,
                    )
                ]
            else:
                self._ai_debug("normalize.actions.empty -> inject stop_and_report('AI 未返回可执行 actions')")
                action_models = [AIAction(type="stop_and_report", final_reason="AI 未返回可执行 actions")]

        self._ai_debug(
            "normalize.result "
            f"issue={issue}, confidence={confidence:.2f}, actions="
            f"{json.dumps([self._serialize_ai_action(a) for a in action_models], ensure_ascii=False)}"
        )

        return AIResult(
            primary_issue=issue,
            confidence=confidence,
            reason=reason,
            actions=action_models,
            thought_chain=thought_chain,
            input_summary=input_summary,
            hit_deleted_mods=hit_deleted_mods,
            dependency_chains=dependency_chains,
            deletion_rationale=deletion_rationale,
            conflicts_or_exceptions=conflicts_or_exceptions,
            user_summary=user_summary,
            suggested_manual_steps=suggested_manual_steps,
            evidence=evidence,
        )

    def _build_openai_messages(self, prompt: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": "你是一个专业的Minecraft服务器部署与优化助手，请严格输出JSON。"},
            {"role": "user", "content": prompt},
        ]

    def _build_openai_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        api_key = (self.builder.config.ai.api_key or "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _resolve_openai_chat_endpoint(self) -> str:
        ai_cfg = self.builder.config.ai
        base_url = (ai_cfg.base_url or "").strip()
        if base_url:
            chat_path = (ai_cfg.chat_path or "/v1/chat/completions").strip() or "/v1/chat/completions"
            return f"{base_url.rstrip('/')}/{chat_path.lstrip('/')}"
        endpoint = (ai_cfg.endpoint or "").strip()
        if endpoint:
            return endpoint
        raise ValueError("openai_compatible 缺少可用 endpoint/base_url")

    def _extract_openai_text_from_non_stream(self, body: dict) -> str:
        choices = body.get("choices") or []
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first.get("message"), dict) else {}
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if not isinstance(item, dict):
                    continue
                text_val = item.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
            return "".join(parts)
        text = first.get("text")
        return text if isinstance(text, str) else ""

    def _extract_openai_text_from_stream(self, resp: requests.Response) -> str:
        chunks: list[str] = []
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data:
                continue
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                self._ai_debug(f"openai.stream.skip_invalid_json line={self._truncate_debug_text(data, 300)}")
                continue
            choices = obj.get("choices") or []
            if not isinstance(choices, list) or not choices:
                continue
            first = choices[0] if isinstance(choices[0], dict) else {}
            delta = first.get("delta") if isinstance(first.get("delta"), dict) else {}
            piece = delta.get("content")
            if isinstance(piece, str):
                chunks.append(piece)
                continue
            if isinstance(piece, list):
                for item in piece:
                    if isinstance(item, str):
                        chunks.append(item)
                        continue
                    if not isinstance(item, dict):
                        continue
                    text_val = item.get("text")
                    if isinstance(text_val, str):
                        chunks.append(text_val)
                continue
            text = first.get("text")
            if isinstance(text, str):
                chunks.append(text)
        return "".join(chunks)

    def _map_ai_http_error(self, status_code: int, body_preview: str = "") -> str:
        if status_code == 401:
            return "AI 鉴权失败(401)，请检查 api_key"
        if status_code == 429:
            return "AI 请求限流(429)，请稍后重试或降低频率"
        if 500 <= status_code <= 599:
            return f"AI 服务端异常({status_code})，请稍后重试"
        if status_code == 400:
            return "AI 请求参数错误(400)，请检查 model/messages/采样参数"
        if status_code == 403:
            return "AI 请求被拒绝(403)，请检查账号权限或网关策略"
        return f"AI HTTP错误({status_code}) body={self._truncate_debug_text(body_preview, 180)}"

    def _call_ollama_generate(self, prompt: str) -> str:
        payload = {"model": self.builder.config.ai.model, "prompt": prompt, "stream": False}
        timeout_sec = max(5, int(self.builder.config.ai.timeout_sec or 300))
        max_retries = max(0, int(self.builder.config.ai.max_retries or 0))
        backoff = max(0.1, float(self.builder.config.ai.retry_backoff_sec or 1.0))
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                resp = requests.post(self.builder.config.ai.endpoint, json=payload, timeout=timeout_sec)
                if resp.status_code >= 400:
                    raise RuntimeError(self._map_ai_http_error(resp.status_code, body_preview=resp.text))
                body = resp.json()
                if not isinstance(body, dict):
                    raise ValueError("ollama_response_not_dict")
                text = body.get("response", "")
                if not isinstance(text, str):
                    text = str(text)
                if not text.strip():
                    thinking = body.get("thinking", "")
                    if isinstance(thinking, str):
                        text = thinking
                    elif isinstance(thinking, list):
                        text = "\n".join(str(x) for x in thinking if x is not None)
                    elif isinstance(thinking, dict):
                        text = json.dumps(thinking, ensure_ascii=False)
                    elif thinking is not None:
                        text = str(thinking)
                    self._ai_debug(
                        "ollama.response.fallback "
                        f"source=thinking used={bool((text or '').strip())}, thinking_type={type(thinking).__name__}"
                    )
                self._ai_debug(
                    "ollama.response "
                    f"status={resp.status_code}, keys={sorted(body.keys())}, response_preview="
                    f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                )
                return text
            except Exception as e:
                last_error = e
                retryable = isinstance(e, (requests.Timeout, requests.ConnectionError))
                if not retryable and isinstance(e, RuntimeError):
                    retryable = "(429)" in str(e) or "AI 服务端异常(" in str(e)
                self._ai_debug(f"ollama.retry attempt={attempt}/{max_retries + 1} retryable={retryable} err={type(e).__name__}:{e}")
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)
        assert last_error is not None
        raise last_error

    def _call_openai_compatible_chat(self, prompt: str) -> str:
        ai_cfg = self.builder.config.ai
        endpoint = self._resolve_openai_chat_endpoint()
        timeout_sec = max(5, int(ai_cfg.timeout_sec or 300))
        max_retries = max(0, int(ai_cfg.max_retries or 0))
        backoff = max(0.1, float(ai_cfg.retry_backoff_sec or 1.0))
        stream = bool(ai_cfg.stream)
        payload: dict[str, object] = {
            "model": ai_cfg.model,
            "messages": self._build_openai_messages(prompt),
            "temperature": float(ai_cfg.temperature),
            "top_p": float(ai_cfg.top_p),
            "max_tokens": int(ai_cfg.max_tokens),
            "stream": stream,
        }
        if ai_cfg.stop:
            payload["stop"] = list(ai_cfg.stop)
        headers = self._build_openai_headers()
        self._ai_debug(
            "openai.request "
            f"endpoint={endpoint}, model={ai_cfg.model}, stream={stream}, payload="
            f"{json.dumps({k: v for k, v in payload.items() if k != 'messages'}, ensure_ascii=False)}"
        )
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                if stream:
                    with requests.post(endpoint, headers=headers, json=payload, timeout=timeout_sec, stream=True) as resp:
                        if resp.status_code >= 400:
                            raise RuntimeError(self._map_ai_http_error(resp.status_code, body_preview=resp.text))
                        text = self._extract_openai_text_from_stream(resp)
                        self._ai_debug(
                            "openai.response.stream "
                            f"status={resp.status_code}, response_preview="
                            f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                        )
                        return text
                resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout_sec)
                if resp.status_code >= 400:
                    raise RuntimeError(self._map_ai_http_error(resp.status_code, body_preview=resp.text))
                body = resp.json()
                if not isinstance(body, dict):
                    raise ValueError("openai_response_not_dict")
                text = self._extract_openai_text_from_non_stream(body)
                self._ai_debug(
                    "openai.response "
                    f"status={resp.status_code}, keys={sorted(body.keys())}, response_preview="
                    f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                )
                return text
            except Exception as e:
                last_error = e
                retryable = isinstance(e, (requests.Timeout, requests.ConnectionError))
                if not retryable and isinstance(e, RuntimeError):
                    retryable = "(429)" in str(e) or "AI 服务端异常(" in str(e)
                self._ai_debug(f"openai.retry attempt={attempt}/{max_retries + 1} retryable={retryable} err={type(e).__name__}:{e}")
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)
        assert last_error is not None
        raise last_error

    def _call_ai_provider(self, prompt: str) -> str:
        provider = (self.builder.config.ai.provider or "ollama").strip().lower()
        if provider in {"openai_compatible", "openai-compatible", "openai"}:
            return self._call_openai_compatible_chat(prompt)
        return self._call_ollama_generate(prompt)

    def _extract_log_signal_lines(self, text: object, limit: int = 12) -> list[str]:
        if not isinstance(text, str) or not text.strip():
            return []
        patterns = (
            "exception",
            "caused by",
            "missing mods",
            "mixin apply failed",
            "unsupported class file major version",
            "could not find required",
            "failed to load",
            "crash",
            "error",
        )
        matches: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lowered = line.lower()
            if any(pat in lowered for pat in patterns):
                matches.append(self._truncate_debug_text(line, 240))
            if len(matches) >= limit:
                break
        return matches

    def build_context_payload(self, context: dict) -> dict[str, object]:
        log_tail = str(context.get("log_tail") or context.get("stdout_tail") or "")
        crash_excerpt = str(context.get("crash_excerpt") or context.get("stderr_tail") or "")
        crash_mod_issue = str(context.get("crash_mod_issue") or "")
        raw_evidence = self._extract_log_signal_lines(log_tail, limit=10)
        raw_evidence.extend(self._extract_log_signal_lines(crash_excerpt, limit=10))
        raw_evidence.extend(self._extract_log_signal_lines(crash_mod_issue, limit=10))
        candidate_fixes = [
            {"type": "remove_mods", "when": "日志或依赖链能明确定位问题 mod"},
            {
                "type": "restore_mods_and_continue",
                "when": "上一轮是带回滚验证的删 mod，且本轮 crash-reports / 崩溃特征已变化，说明应恢复到删前基线再继续分析",
            },
            {"type": "bisect_mods", "when": "无法直接定位单个问题 mod，但可以对可疑 mod 集合进行受控二分测试"},
            {"type": "adjust_memory", "when": "存在内存分配不足或 OOM 证据"},
            {"type": "change_java", "when": "存在 Java 版本不兼容证据"},
            {"type": "report_manual_fix", "when": "没有安全自动修复动作但可以给出人工修复建议"},
            {"type": "stop_and_report", "when": "证据不足，只能保守停止"},
        ]
        return {
            "server_profile": {
                "mc_version": context.get("mc_version", "unknown"),
                "loader": context.get("loader", "unknown"),
                "jvm_args": context.get("jvm_args", "unknown"),
                "available_ram": context.get("available_ram", "unknown"),
                "attempt": self.builder.attempts_used,
            },
            "failure_signals": {
                "conflicts_or_exceptions": self._normalize_text_list(context.get("conflicts_or_exceptions", []), limit=20),
                "port_open_detected": context.get("port_open_detected", False),
                "done_detected": context.get("done_detected", False),
                "command_probe_detected": context.get("command_probe_detected", False),
            },
            "mod_state": {
                "mod_count": context.get("mod_count", 0),
                "current_installed_mods": self._normalize_text_list(context.get("current_installed_mods", []), limit=120),
                "current_installed_client_mods": self._normalize_text_list(context.get("current_installed_client_mods", []), limit=120),
                "known_deleted_client_mods": self._normalize_text_list(context.get("known_deleted_client_mods", []), limit=120),
                "deleted_mod_evidence": context.get("deleted_mod_evidence", {}),
            },
            "rollback_state": {
                "last_rollback_remove_mods": context.get("last_rollback_remove_mods", {}),
                "crash_reports_changed_since_last_rollback_remove": bool(
                    context.get("crash_reports_changed_since_last_rollback_remove", False)
                ),
                "last_crash_reports": self._normalize_text_list(context.get("last_crash_reports", []), limit=20),
                "current_crash_reports": self._normalize_text_list(context.get("current_crash_reports", []), limit=20),
                "crash_report_delta": self._normalize_text_list(context.get("crash_report_delta", []), limit=20),
                "last_crash_excerpt_preview": self._truncate_debug_text(context.get("last_crash_excerpt", ""), 1500),
            },
            "bisect_state": {
                "active": bool(context.get("bisect_active", False)),
                "phase": str(context.get("bisect_phase", "initial") or "initial"),
                "next_allowed_requests": self._normalize_text_list(context.get("bisect_next_allowed_requests", []), limit=10),
                "last_feedback": context.get("bisect_feedback", {}),
                "fallback_targets": self._normalize_text_list(context.get("bisect_fallback_targets", []), limit=120),
                "suspects_invalidated": bool(context.get("bisect_suspects_invalidated", False)),
                "success_ready": bool(context.get("bisect_success_ready", False)),
                "success_guard_reason": str(context.get("bisect_success_guard_reason", "") or ""),
                "success_guard_history": self._normalize_text_list(context.get("bisect_success_guard_history", []), limit=8),
                "consecutive_same_issue_on_success": int(context.get("bisect_consecutive_same_issue_on_success", 0) or 0),
            },
            "recent_actions": self._normalize_text_list(context.get("recent_actions", []), limit=20),
            "candidate_fixes": candidate_fixes,
            "raw_evidence": {
                "log_signals": raw_evidence[:20],
                "log_tail_preview": self._truncate_debug_text(log_tail, 2000),
                "crash_excerpt_preview": self._truncate_debug_text(crash_excerpt, 2000),
                "crash_mod_issue_preview": self._truncate_debug_text(crash_mod_issue, 2000),
            },
        }

    def build_prompt(self, context: dict) -> str:
        schema = {
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
                        "type": "restore_mods_and_continue",
                        "reason": "上一轮 rollback_on_failure 删除后，当前 crash-reports 已变化，需要恢复到删前基线后继续分析",
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
        return "".join(
            [
                "你是一个专业的Minecraft服务器部署与优化助手。\n",
                "任务目标：先识别主因，再选择最安全、最可执行的动作。"
                "证据优先级：异常堆栈/错误关键字 > 已删除客户端mod依赖链 > 最近自动操作 > 其他上下文。\n",
                "硬规则：1. 若某个 mod 依赖任何已知且已删除的客户端 mod，则该 mod 必须判定为 remove_mods。"
                "2. 若证据只能唯一锁定 1 个候选，则 remove_mods 只提交这 1 个最有把握的 mod。"
                "但若证据已明确表明多个 mod 都是客户端专用 mod，允许一次提交多个 remove_mods targets；"
                "不过总数绝不能超过系统源码中的安全上限（当前为 3 个）。"
                "3. 对 remove_mods，若你希望系统在删除后做一次启动验证并在失败时自动回滚，"
                "则显式输出 rollback_on_failure=true。"
                "4. 若 rollback_state.last_rollback_remove_mods.triggered=true，且上一轮是 remove_mods + rollback_on_failure=true，"
                "同时 rollback_state.crash_reports_changed_since_last_rollback_remove=true，"
                "则允许优先输出 restore_mods_and_continue，用于要求系统恢复到上一轮删前基线并继续后续自动动作；"
                "此时必须结合 last_crash_reports、current_crash_reports、"
                "crash_report_delta、last_crash_excerpt_preview 判断崩溃是否真的变了。"
                "若 crash 没变，则禁止输出 restore_mods_and_continue。"
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
                "2. 若上一轮 remove_mods 已触发自动回滚，且 crash 报告或关键崩溃特征明显变化，优先 restore_mods_and_continue；"
                "若 crash 报告未变，则不要把 restore_mods_and_continue 当作默认动作。"
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

    def analyze(self, context: dict) -> dict:
        if not self.builder.config.ai.enabled:
            result = AIResult(
                primary_issue="other",
                confidence=0.2,
                reason="AI未启用，返回保守策略",
                actions=[AIAction(type="stop_and_report", final_reason="AI disabled")],
            )
            self.builder.last_ai_result = result
            self.builder.last_ai_payload = {}
            self.builder.last_ai_manual_report = {}
            return {
                "primary_issue": result.primary_issue,
                "confidence": result.confidence,
                "reason": result.reason,
                "thought_chain": [],
                "input_summary": "",
                "hit_deleted_mods": [],
                "dependency_chains": [],
                "deletion_rationale": [],
                "conflicts_or_exceptions": [],
                "user_summary": "",
                "suggested_manual_steps": [],
                "evidence": [],
                "actions": [self._serialize_ai_action(a) for a in result.actions],
            }

        normalized_context = self.build_context_payload(context)
        prompt = self.build_prompt(normalized_context)
        provider = (self.builder.config.ai.provider or "ollama").strip().lower()
        self._ai_debug(
            "request.prepare "
            f"provider={provider}, endpoint={self.builder.config.ai.endpoint}, model={self.builder.config.ai.model}, "
            f"context_keys={sorted(normalized_context.keys())}, prompt_len={len(prompt)}, "
            f"prompt_preview={json.dumps(self._truncate_debug_text(prompt, 800), ensure_ascii=False)}"
        )
        try:
            text = self._call_ai_provider(prompt)
            self._ai_debug(f"response.raw len={len(str(text))}")
            parsed = self._extract_json_object(str(text))
            if not isinstance(parsed, dict):
                self._ai_debug("response.parse failed reason=no_json_object attempt=1 -> retry_once")
                retry_text = self._call_ai_provider(prompt)
                self._ai_debug(f"response.raw.retry len={len(str(retry_text))}")
                parsed = self._extract_json_object(str(retry_text))
                if not isinstance(parsed, dict):
                    self._ai_debug("response.parse failed reason=no_json_object attempt=2")
                    raise ValueError("ai_response_invalid_json")
            self._ai_debug(f"response.parse success parsed={json.dumps(parsed, ensure_ascii=False)[:2000]}")
            self.builder.last_ai_payload = parsed
            result = self._normalize_ai_result(parsed)
        except Exception as e:
            err = f"AI 分析失败: {type(e).__name__}:{e}"
            self.builder.operations.append(f"analyze_with_ai_failed:{type(e).__name__}")
            self.builder._log("install.ai", err, level="WARN")
            self._ai_debug(f"request.exception detail={self._truncate_debug_text(traceback.format_exc(), 2000)}")
            self.builder.last_ai_payload = {}
            result = self._safe_ai_result(reason=err, confidence=0.05)

        self.builder.last_ai_result = result
        self.builder.last_ai_manual_report = {
            "user_summary": result.user_summary,
            "suggested_manual_steps": list(result.suggested_manual_steps),
            "evidence": list(result.evidence),
        }
        self._ai_debug(
            "analysis.value "
            f"input_summary={self._truncate_debug_text(result.input_summary or 'none', 400)}; "
            f"hit_deleted_mods={json.dumps(result.hit_deleted_mods, ensure_ascii=False)}; "
            f"dependency_chains={json.dumps(result.dependency_chains, ensure_ascii=False)[:800]}"
        )
        self._ai_debug(
            "analysis.judgement "
            f"deletion_rationale={json.dumps(result.deletion_rationale, ensure_ascii=False)[:800]}; "
            f"conflicts_or_exceptions={json.dumps(result.conflicts_or_exceptions, ensure_ascii=False)[:600]}"
        )
        self._ai_debug(
            "result.final "
            f"issue={result.primary_issue}, confidence={result.confidence:.2f}, reason={result.reason}, "
            f"actions={json.dumps([self._serialize_ai_action(a) for a in result.actions], ensure_ascii=False)}"
        )
        return {
            "primary_issue": result.primary_issue,
            "confidence": result.confidence,
            "reason": result.reason,
            "thought_chain": list(result.thought_chain),
            "input_summary": result.input_summary,
            "hit_deleted_mods": list(result.hit_deleted_mods),
            "dependency_chains": [list(x) for x in result.dependency_chains],
            "deletion_rationale": list(result.deletion_rationale),
            "conflicts_or_exceptions": list(result.conflicts_or_exceptions),
            "user_summary": result.user_summary,
            "suggested_manual_steps": list(result.suggested_manual_steps),
            "evidence": list(result.evidence),
            "actions": [self._serialize_ai_action(a) for a in result.actions],
        }

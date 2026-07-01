from __future__ import annotations

import json
import re
import time
import traceback
from dataclasses import asdict, fields, is_dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

import requests

from .ai_prompts import (
    build_json_repair_prompt,
    build_prompt,
    build_remove_validation_prompt,
    build_response_format,
    build_structured_output_schema,
    build_success_guard_prompt,
    normal_failure_schema_example,
    remove_validation_schema_example,
    success_guard_schema_example,
)
from .models import AIAction, AIResult
from .util import (
    ExternalDataError,
    ExternalRequestError,
    ExternalResponseError,
    ExternalServiceError,
    configure_requests_session,
)

if TYPE_CHECKING:
    from .builder import ServerBuilder


class UnsupportedStructuredOutputError(ExternalServiceError):
    pass


class UnsupportedToolCallError(ExternalServiceError):
    pass


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

        if is_dataclass(action) and not isinstance(action, type):
            return asdict(action)

        if hasattr(action, "model_dump") and callable(getattr(action, "model_dump")):
            dumped = cast(Any, action).model_dump()
            return dumped if isinstance(dumped, dict) else {"type": str(action)}

        if hasattr(action, "dict") and callable(getattr(action, "dict")):
            dumped = cast(Any, action).dict()
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

    def _normal_failure_schema_example(self) -> dict[str, object]:
        return normal_failure_schema_example(self)

    def _success_guard_schema_example(self) -> dict[str, object]:
        return success_guard_schema_example(self)

    def _remove_validation_schema_example(self) -> dict[str, object]:
        return remove_validation_schema_example(self)

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
            "continue_after_restore_mods",
            "adjust_memory",
            "change_java",
            "stop_and_report",
            "report_manual_fix",
            "bisect_mods",
            "move_bisect_mods",
            "switch_recognition_candidate",
        }
        action_literal_map: dict[str, Literal[
            "remove_mods",
            "continue_after_restore_mods",
            "adjust_memory",
            "change_java",
            "stop_and_report",
            "report_manual_fix",
            "bisect_mods",
            "move_bisect_mods",
            "switch_recognition_candidate",
        ]] = {name: cast(Any, name) for name in allowed_action}

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
            confidence = float(cast(Any, confidence_raw))
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
                action_models.append(AIAction(type=action_literal_map[action_type]))

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

    def _build_openai_tool_messages(self, prompt: str) -> list[dict[str, str]]:
        return [
            {
                "role": "system",
                "content": (
                    "你是一个专业的Minecraft服务器部署与优化助手。"
                    "必须通过提供的函数工具一次性提交最终结构化结论，不要直接输出 JSON 文本，不要输出 markdown。"
                ),
            },
            {"role": "user", "content": prompt},
        ]

    def _build_structured_output_schema(self, allowed_action_types: list[str]) -> dict[str, object]:
        return build_structured_output_schema(self, allowed_action_types)

    def _build_openai_tool(self, name: str, allowed_action_types: list[str]) -> dict[str, object]:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": "提交最终的结构化分析结论与下一步动作。必须且只能调用一次。",
                "parameters": self._build_structured_output_schema(allowed_action_types),
            },
        }

    def _build_response_format(self, name: str, allowed_action_types: list[str]) -> dict[str, object]:
        return build_response_format(self, name, allowed_action_types)

    def _build_json_repair_prompt(self, raw_text: str, schema_example: dict[str, object]) -> str:
        return build_json_repair_prompt(self, raw_text, schema_example)

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

    def _extract_openai_message_from_non_stream(self, body: dict) -> dict[str, object]:
        choices = body.get("choices") or []
        if not isinstance(choices, list) or not choices:
            return {}
        first = choices[0] if isinstance(choices[0], dict) else {}
        message_obj = first.get("message")
        return message_obj if isinstance(message_obj, dict) else {}

    def _extract_openai_text_from_non_stream(self, body: dict) -> str:
        message = self._extract_openai_message_from_non_stream(body)
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
        choices = body.get("choices") or []
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0] if isinstance(choices[0], dict) else {}
        text = first.get("text")
        return text if isinstance(text, str) else ""

    def _parse_openai_function_arguments(self, value: object, *, provider: str, function_name: str) -> dict[str, object] | None:
        if isinstance(value, dict):
            return {str(k): v for k, v in value.items()}
        if not isinstance(value, str):
            return None
        arguments_text = value.strip()
        if not arguments_text:
            return None
        try:
            parsed = json.loads(arguments_text)
        except json.JSONDecodeError as exc:
            raise ExternalDataError(
                f"AI 响应解析失败({provider}): invalid_tool_arguments tool={function_name}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ExternalDataError(
                f"AI 响应解析失败({provider}): tool_arguments_not_dict tool={function_name}"
            )
        return parsed

    def _extract_openai_tool_payload(
        self,
        provider: str,
        body: dict,
        *,
        expected_tool_name: str | None = None,
    ) -> dict[str, object] | None:
        message = self._extract_openai_message_from_non_stream(body)
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            for tool_call in tool_calls:
                if not isinstance(tool_call, dict):
                    continue
                function_obj = tool_call.get("function")
                function = function_obj if isinstance(function_obj, dict) else {}
                function_name = str(function.get("name") or "").strip()
                if expected_tool_name and function_name != expected_tool_name:
                    continue
                parsed = self._parse_openai_function_arguments(
                    function.get("arguments"),
                    provider=provider,
                    function_name=function_name or expected_tool_name or "unknown",
                )
                if isinstance(parsed, dict):
                    return parsed
        function_call = message.get("function_call")
        if isinstance(function_call, dict):
            function_name = str(function_call.get("name") or "").strip()
            if expected_tool_name and function_name and function_name != expected_tool_name:
                return None
            return self._parse_openai_function_arguments(
                function_call.get("arguments"),
                provider=provider,
                function_name=function_name or expected_tool_name or "unknown",
            )
        return None

    def _extract_openai_text_from_stream(self, resp: requests.Response) -> str:
        chunks: list[str] = []
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            if isinstance(raw_line, bytes):
                line = raw_line.decode("utf-8", errors="ignore").strip()
            else:
                line = str(raw_line).strip()
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
            delta_obj = first.get("delta")
            delta = delta_obj if isinstance(delta_obj, dict) else {}
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

    def _raise_ai_request_error(self, provider: str, exc: requests.RequestException) -> None:
        raise ExternalRequestError(f"AI 请求失败({provider}): {type(exc).__name__}:{exc}") from exc

    def _raise_ai_http_error(self, provider: str, resp: requests.Response) -> None:
        raise ExternalResponseError(
            f"AI 服务返回非成功状态({provider}): {self._map_ai_http_error(resp.status_code, body_preview=resp.text)}"
        )

    def _is_retryable_ai_error(self, exc: Exception) -> bool:
        if isinstance(exc, (requests.Timeout, requests.ConnectionError, ExternalRequestError)):
            return True
        if isinstance(exc, ExternalResponseError):
            message = str(exc)
            return "(429)" in message or "AI 服务端异常(" in message
        return False

    def _is_unsupported_structured_output_response(self, status_code: int, body_preview: str) -> bool:
        if status_code != 400:
            return False
        lowered = (body_preview or "").lower()
        markers = (
            "response_format",
            "json_schema",
            "unsupported",
            "unknown parameter",
            "invalid parameter",
            "not supported",
        )
        return any(marker in lowered for marker in markers)

    def _is_unsupported_tool_call_response(self, status_code: int, body_preview: str) -> bool:
        if status_code != 400:
            return False
        lowered = (body_preview or "").lower()
        parameter_markers = ("tools", "tool_choice", "tool_calls", "function_call", "functions")
        reason_markers = (
            "unsupported",
            "unknown parameter",
            "invalid parameter",
            "unknown field",
            "not supported",
            "extra inputs are not permitted",
        )
        return any(marker in lowered for marker in parameter_markers) and any(marker in lowered for marker in reason_markers)

    def _log_ai_retry(self, provider: str, attempt: int, max_attempts: int, retryable: bool, exc: Exception) -> None:
        self._ai_debug(
            f"{provider}.retry attempt={attempt}/{max_attempts} retryable={retryable} "
            f"err={type(exc).__name__}:{exc}"
        )

    def _parse_json_body(self, provider: str, resp: requests.Response) -> dict:
        try:
            body = resp.json()
        except ValueError as exc:
            raise ExternalDataError(f"AI 响应解析失败({provider}): invalid_json") from exc
        if not isinstance(body, dict):
            raise ExternalDataError(f"AI 响应解析失败({provider}): response_not_dict")
        return body

    def _call_ollama_generate(self, prompt: str) -> str:
        payload = {"model": self.builder.config.ai.model, "prompt": prompt, "stream": False}
        timeout_sec = max(5, int(self.builder.config.ai.timeout_sec or 300))
        max_retries = max(0, int(self.builder.config.ai.max_retries or 0))
        backoff = max(0.1, float(self.builder.config.ai.retry_backoff_sec or 1.0))
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                try:
                    with configure_requests_session(
                        requests.Session(),
                        proxies=self.builder.config.proxy.to_requests_proxies(),
                        trust_env=self.builder.config.proxy.trust_env,
                    ) as session:
                        resp = session.post(self.builder.config.ai.endpoint, json=cast(Any, payload), timeout=timeout_sec)
                except requests.RequestException as exc:
                    self._raise_ai_request_error("ollama", exc)
                if resp.status_code >= 400:
                    self._raise_ai_http_error("ollama", resp)
                body = self._parse_json_body("ollama", resp)
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
            except (ExternalRequestError, ExternalResponseError, ExternalDataError) as e:
                last_error = e
                retryable = self._is_retryable_ai_error(e)
                self._log_ai_retry("ollama", attempt, max_retries + 1, retryable, e)
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)
        assert last_error is not None
        raise last_error

    def _call_openai_compatible_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        allowed_action_types: list[str],
    ) -> dict[str, object]:
        ai_cfg = self.builder.config.ai
        endpoint = self._resolve_openai_chat_endpoint()
        timeout_sec = max(5, int(ai_cfg.timeout_sec or 300))
        max_retries = max(0, int(ai_cfg.max_retries or 0))
        backoff = max(0.1, float(ai_cfg.retry_backoff_sec or 1.0))
        payload: dict[str, object] = {
            "model": ai_cfg.model,
            "messages": self._build_openai_tool_messages(prompt),
            "temperature": float(ai_cfg.temperature),
            "top_p": float(ai_cfg.top_p),
            "max_tokens": int(ai_cfg.max_tokens),
            "stream": False,
            "tools": [self._build_openai_tool(tool_name, allowed_action_types)],
            "tool_choice": {"type": "function", "function": {"name": tool_name}},
        }
        if ai_cfg.stop:
            payload["stop"] = list(ai_cfg.stop)
        headers = self._build_openai_headers()
        self._ai_debug(
            "openai.request.tool "
            f"endpoint={endpoint}, model={ai_cfg.model}, payload="
            f"{json.dumps({k: v for k, v in payload.items() if k != 'messages'}, ensure_ascii=False)}"
        )
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                try:
                    with configure_requests_session(
                        requests.Session(),
                        proxies=self.builder.config.proxy.to_requests_proxies(),
                        trust_env=self.builder.config.proxy.trust_env,
                    ) as session:
                        resp = session.post(endpoint, headers=headers, json=cast(Any, payload), timeout=timeout_sec)
                except requests.RequestException as exc:
                    self._raise_ai_request_error("openai_compatible", exc)
                if resp.status_code >= 400:
                    if self._is_unsupported_tool_call_response(resp.status_code, resp.text):
                        raise UnsupportedToolCallError(
                            "AI 原生 tool call 不受支持(openai_compatible): "
                            f"{self._map_ai_http_error(resp.status_code, body_preview=resp.text)}"
                        )
                    self._raise_ai_http_error("openai_compatible", resp)
                body = self._parse_json_body("openai_compatible", resp)
                parsed = self._extract_openai_tool_payload(
                    "openai_compatible",
                    body,
                    expected_tool_name=tool_name,
                )
                if isinstance(parsed, dict):
                    self._ai_debug(
                        "openai.response.tool "
                        f"status={resp.status_code}, tool={tool_name}, parsed_preview="
                        f"{json.dumps(self._truncate_debug_text(json.dumps(parsed, ensure_ascii=False), 1200), ensure_ascii=False)}"
                    )
                    return parsed
                text = self._extract_openai_text_from_non_stream(body)
                parsed_from_content = self._extract_json_object(text)
                if isinstance(parsed_from_content, dict):
                    self._ai_debug(
                        "openai.response.tool_fallback "
                        f"status={resp.status_code}, source=message_content_json, tool={tool_name}"
                    )
                    return parsed_from_content
                raise ExternalDataError("AI 响应解析失败(openai_compatible): missing_tool_call")
            except (ExternalRequestError, ExternalResponseError, ExternalDataError, UnsupportedToolCallError) as e:
                last_error = e
                if isinstance(e, UnsupportedToolCallError):
                    break
                retryable = self._is_retryable_ai_error(e)
                self._log_ai_retry("openai.tool", attempt, max_retries + 1, retryable, e)
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)
        assert last_error is not None
        raise last_error

    def _call_openai_compatible_chat(self, prompt: str, response_format: dict[str, object] | None = None) -> str:
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
        if response_format:
            payload["response_format"] = dict(response_format)
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
                    try:
                        request_ctx = configure_requests_session(
                            requests.Session(),
                            proxies=self.builder.config.proxy.to_requests_proxies(),
                            trust_env=self.builder.config.proxy.trust_env,
                        ).post(endpoint, headers=headers, json=cast(Any, payload), timeout=timeout_sec, stream=True)
                    except requests.RequestException as exc:
                        self._raise_ai_request_error("openai_compatible", exc)
                    with request_ctx as resp:
                        if resp.status_code >= 400:
                            if response_format and self._is_unsupported_structured_output_response(resp.status_code, resp.text):
                                message = self._map_ai_http_error(resp.status_code, body_preview=resp.text)
                                raise UnsupportedStructuredOutputError(
                                    f"AI 结构化输出不受支持(openai_compatible): {message}"
                                )
                            self._raise_ai_http_error("openai_compatible", resp)
                        text = self._extract_openai_text_from_stream(resp)
                        self._ai_debug(
                            "openai.response.stream "
                            f"status={resp.status_code}, response_preview="
                            f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                        )
                        return text
                try:
                    with configure_requests_session(
                        requests.Session(),
                        proxies=self.builder.config.proxy.to_requests_proxies(),
                        trust_env=self.builder.config.proxy.trust_env,
                    ) as session:
                        resp = session.post(endpoint, headers=headers, json=cast(Any, payload), timeout=timeout_sec)
                except requests.RequestException as exc:
                    self._raise_ai_request_error("openai_compatible", exc)
                if resp.status_code >= 400:
                    if response_format and self._is_unsupported_structured_output_response(resp.status_code, resp.text):
                        raise UnsupportedStructuredOutputError(
                            f"AI 结构化输出不受支持(openai_compatible): {self._map_ai_http_error(resp.status_code, body_preview=resp.text)}"
                        )
                    self._raise_ai_http_error("openai_compatible", resp)
                body = self._parse_json_body("openai_compatible", resp)
                text = self._extract_openai_text_from_non_stream(body)
                self._ai_debug(
                    "openai.response "
                    f"status={resp.status_code}, keys={sorted(body.keys())}, response_preview="
                    f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                )
                return text
            except (ExternalRequestError, ExternalResponseError, ExternalDataError, UnsupportedStructuredOutputError) as e:
                last_error = e
                if isinstance(e, UnsupportedStructuredOutputError):
                    break
                retryable = self._is_retryable_ai_error(e)
                self._log_ai_retry("openai", attempt, max_retries + 1, retryable, e)
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)
        assert last_error is not None
        raise last_error

    def _call_ai_provider(self, prompt: str, response_format: dict[str, object] | None = None) -> str:
        provider = (self.builder.config.ai.provider or "ollama").strip().lower()
        if provider in {"openai_compatible", "openai-compatible", "openai"}:
            return self._call_openai_compatible_chat(prompt, response_format=response_format)
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
                "type": "continue_after_restore_mods",
                "when": "专项删除验证已确认故障形态变化，说明应恢复到删除后的工作集并基于该轮新证据继续常规分析",
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
                "loader_version": context.get("loader_version"),
                "build": context.get("build"),
                "start_mode": context.get("start_mode", "unknown"),
                "jvm_args": context.get("jvm_args", "unknown"),
                "available_ram": context.get("available_ram", "unknown"),
                "attempt": int(getattr(self.builder, "attempts_used", 0) or 0),
            },
            "recognition_state": {
                "recognition_summary": dict(context.get("recognition_summary", {}))
                if isinstance(context.get("recognition_summary"), dict)
                else {},
            },
            "startup_state": {
                "conflicts_or_exceptions": self._normalize_text_list(context.get("conflicts_or_exceptions", []), limit=20),
                "failure_signals": self._normalize_text_list(context.get("failure_signals", []), limit=20),
                "readiness_evidence": self._normalize_text_list(context.get("readiness_evidence", []), limit=20),
                "port_open_detected": context.get("port_open_detected", False),
                "done_detected": context.get("done_detected", False),
                "command_probe_detected": context.get("command_probe_detected", False),
                "resource_summary": dict(context.get("resource_summary", {})) if isinstance(context.get("resource_summary"), dict) else {},
                "key_exception": str(context.get("key_exception") or "unknown"),
                "suspected_mods": self._normalize_text_list(context.get("suspected_mods", []), limit=30),
                "oom_detected": bool(context.get("oom_detected", False)),
                "jvm_exit_code": context.get("jvm_exit_code"),
            },
            "deterministic_tools": {
                "start_command_check": dict(context.get("start_command_check", {}))
                if isinstance(context.get("start_command_check"), dict)
                else {},
                "crash_report_analysis": dict(context.get("crash_report_analysis", {}))
                if isinstance(context.get("crash_report_analysis"), dict)
                else {},
                "dependency_graph": dict(context.get("dependency_graph", {}))
                if isinstance(context.get("dependency_graph"), dict)
                else {},
                "mod_metadata_summary": dict(context.get("mod_metadata_summary", {}))
                if isinstance(context.get("mod_metadata_summary"), dict)
                else {},
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

    def build_success_guard_context_payload(self, context: dict) -> dict[str, object]:
        base = self.build_context_payload(context)
        base["analysis_stage"] = "success_guard"
        base["allowed_actions"] = [
            {"type": "remove_mods", "when": "成功态证据已能锁定剩余客户端模组或冲突模组"},
            {"type": "bisect_mods", "when": "成功态仍有待验证的另一组或失败组，需要继续受控二分"},
            {"type": "move_bisect_mods", "when": "当前成功组缺少前置依赖，需要从另一组临时迁移少量依赖"},
            {"type": "report_manual_fix", "when": "成功态仍存在风险，但自动动作不再安全"},
            {"type": "stop_and_report", "when": "成功态证据不足，保守停止"},
        ]
        return base

    def build_remove_validation_context_payload(self, context: dict) -> dict[str, object]:
        validation_state = dict(context.get("remove_validation_state") or {})
        return {
            "validation_target": {
                "attempt": int(getattr(self.builder, "attempts_used", 0) or 0),
                "action_index": validation_state.get("action_index"),
                "removed_targets": self._normalize_text_list(validation_state.get("removed_targets", []), limit=20),
                "forced_targets": self._normalize_text_list(validation_state.get("forced_targets", []), limit=20),
            },
            "failure_comparison": {
                "previous_crash_reports": self._normalize_text_list(validation_state.get("previous_crash_reports", []), limit=20),
                "validation_crash_reports": self._normalize_text_list(validation_state.get("validation_crash_reports", []), limit=20),
                "crash_report_delta": self._normalize_text_list(validation_state.get("crash_report_delta", []), limit=20),
                "previous_excerpt_preview": self._truncate_debug_text(validation_state.get("previous_excerpt", ""), 1200),
                "validation_excerpt_preview": self._truncate_debug_text(validation_state.get("validation_excerpt", ""), 1200),
                "failure_signals": self._normalize_text_list(validation_state.get("failure_signals", []), limit=20),
                "readiness_evidence": self._normalize_text_list(validation_state.get("readiness_evidence", []), limit=20),
                "problem_changed": bool(validation_state.get("problem_changed", False)),
            },
            "allowed_actions": [
                {
                    "type": "continue_after_restore_mods",
                    "when": (
                        "删除验证后故障形态发生变化，说明删除命中了问题方向；"
                        "系统会在上一轮结束时先恢复删前基线，随后本轮再恢复到删除后的工作集继续阶段二"
                    ),
                },
                {"type": "stop_and_report", "when": "删除验证没有提供足够的新信息，不应继续消费自动动作"},
                {
                    "type": "report_manual_fix",
                    "when": "删除验证已能明确说明原因，但自动动作仍不安全，改为输出人工处理建议",
                },
            ],
        }

    def build_remove_validation_prompt(self, context: dict) -> str:
        return build_remove_validation_prompt(self, context)

    def build_success_guard_prompt(self, context: dict) -> str:
        return build_success_guard_prompt(self, context)

    def build_prompt(self, context: dict) -> str:
        return build_prompt(self, context)

    def _provider_prefers_tool_calls(self) -> bool:
        provider = (self.builder.config.ai.provider or "ollama").strip().lower()
        return provider in {"openai_compatible", "openai-compatible", "openai"}

    def _provider_prefers_structured_output(self) -> bool:
        provider = (self.builder.config.ai.provider or "ollama").strip().lower()
        return provider in {"openai_compatible", "openai-compatible", "openai"}

    def _invoke_json_prompt(
        self,
        prompt: str,
        *,
        response_format_name: str,
        schema_example: dict[str, object],
        allowed_action_types: list[str],
    ) -> dict[str, object]:
        if self._provider_prefers_tool_calls():
            try:
                return self._call_openai_compatible_tool(
                    prompt,
                    tool_name=response_format_name,
                    allowed_action_types=allowed_action_types,
                )
            except UnsupportedToolCallError:
                self._ai_debug(f"response.tool.unsupported name={response_format_name}")
            except ExternalDataError as exc:
                self._ai_debug(
                    "response.tool.invalid "
                    f"name={response_format_name} err={type(exc).__name__}:{self._truncate_debug_text(exc, 400)}"
                )

        response_format = (
            self._build_response_format(response_format_name, allowed_action_types)
            if self._provider_prefers_structured_output()
            else None
        )
        structured_output_unsupported = False
        try:
            text = self._call_ai_provider(prompt, response_format=response_format)
        except UnsupportedStructuredOutputError:
            structured_output_unsupported = True
            self._ai_debug(f"response.structured.unsupported name={response_format_name}")
            text = self._call_ai_provider(prompt)

        parsed = self._extract_json_object(str(text))
        if isinstance(parsed, dict):
            return parsed

        self._ai_debug(f"response.parse failed reason=no_json_object name={response_format_name} -> repair_prompt")
        repair_prompt = self._build_json_repair_prompt(str(text), schema_example)
        repair_response_format = None if structured_output_unsupported else response_format
        repaired_text = self._call_ai_provider(repair_prompt, response_format=repair_response_format)
        repaired = self._extract_json_object(str(repaired_text))
        if not isinstance(repaired, dict):
            self._ai_debug(f"response.parse failed reason=repair_failed name={response_format_name}")
            raise ValueError("ai_response_invalid_json")
        return repaired

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
            parsed = self._invoke_json_prompt(
                prompt,
                response_format_name="mcasb_normal_failure",
                schema_example=self._normal_failure_schema_example(),
                allowed_action_types=[
                    "remove_mods",
                    "continue_after_restore_mods",
                    "adjust_memory",
                    "change_java",
                    "stop_and_report",
                    "report_manual_fix",
                    "bisect_mods",
                    "move_bisect_mods",
                    "switch_recognition_candidate",
                ],
            )
            self._ai_debug(f"response.parse success parsed={json.dumps(parsed, ensure_ascii=False)[:2000]}")
            self.builder.last_ai_payload = parsed
            result = self._normalize_ai_result(parsed)
        except ExternalServiceError as e:
            err = f"AI 分析失败: {type(e).__name__}:{e}"
            self.builder.operations.append(f"analyze_with_ai_failed:{type(e).__name__}")
            self.builder._log("install.ai", err, level="WARN")
            self._ai_debug(f"request.exception detail={self._truncate_debug_text(traceback.format_exc(), 2000)}")
            self.builder.last_ai_payload = {}
            result = self._safe_ai_result(reason=err, confidence=0.05)
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

    def analyze_success_guard(self, context: dict) -> dict:
        if not self.builder.config.ai.enabled:
            return self.analyze(context)

        normalized_context = self.build_success_guard_context_payload(context)
        prompt = self.build_success_guard_prompt(normalized_context)
        try:
            parsed = self._invoke_json_prompt(
                prompt,
                response_format_name="mcasb_success_guard",
                schema_example=self._success_guard_schema_example(),
                allowed_action_types=[
                    "remove_mods",
                    "bisect_mods",
                    "move_bisect_mods",
                    "report_manual_fix",
                    "stop_and_report",
                ],
            )
            self._ai_debug(f"success_guard.parse success parsed={json.dumps(parsed, ensure_ascii=False)[:2000]}")
            self.builder.last_ai_payload = parsed
            result = self._normalize_ai_result(parsed)
        except ExternalServiceError as e:
            err = f"AI 成功态分析失败: {type(e).__name__}:{e}"
            self.builder.operations.append(f"analyze_success_guard_failed:{type(e).__name__}")
            self.builder._log("install.ai", err, level="WARN")
            result = self._safe_ai_result(reason=err, confidence=0.05)
        except Exception as e:
            err = f"AI 成功态分析失败: {type(e).__name__}:{e}"
            self.builder.operations.append(f"analyze_success_guard_failed:{type(e).__name__}")
            self.builder._log("install.ai", err, level="WARN")
            result = self._safe_ai_result(reason=err, confidence=0.05)

        self.builder.last_ai_result = result
        self.builder.last_ai_manual_report = {
            "user_summary": result.user_summary,
            "suggested_manual_steps": list(result.suggested_manual_steps),
            "evidence": list(result.evidence),
        }
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

    def analyze_remove_validation(self, context: dict) -> dict:
        if not self.builder.config.ai.enabled:
            result = AIResult(
                primary_issue="other",
                confidence=0.2,
                reason="AI未启用，删除验证阶段返回保守策略",
                actions=[AIAction(type="stop_and_report", final_reason="AI disabled")],
            )
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

        normalized_context = self.build_remove_validation_context_payload(context)
        prompt = self.build_remove_validation_prompt(normalized_context)
        try:
            parsed = self._invoke_json_prompt(
                prompt,
                response_format_name="mcasb_remove_validation",
                schema_example=self._remove_validation_schema_example(),
                allowed_action_types=[
                    "continue_after_restore_mods",
                    "report_manual_fix",
                    "stop_and_report",
                ],
            )
            result = self._normalize_ai_result(parsed)
        except ExternalServiceError as e:
            result = self._safe_ai_result(reason=f"AI 删除验证分析失败: {type(e).__name__}:{e}", confidence=0.05)
        except Exception as e:
            result = self._safe_ai_result(reason=f"AI 删除验证分析失败: {type(e).__name__}:{e}", confidence=0.05)
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

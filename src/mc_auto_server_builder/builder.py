from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
import platform
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

import psutil
import requests

from .config import AppConfig
from .defaults import (
    SUPPORTED_JAVA_VERSIONS,
    get_jvm_params_for_java_version,
)
from .input_parser import parse_manifest_from_zip, parse_pack_input
from .models import AIAction, AIResult, PackInput, PackManifest, StartResult, WorkDirs
from .rule_db import RuleDB
from .workspace import backup_directory, create_workdirs


class ServerBuilder:
    def __init__(self, source: str, config: AppConfig | None = None, base_dir: str | Path = "."):
        self.config = config or AppConfig()
        self.pack_input: PackInput = parse_pack_input(source)
        self.base_dir = Path(base_dir).resolve()
        self.workdirs: WorkDirs = create_workdirs(self.base_dir)
        self.rule_db = RuleDB(self.workdirs.db / "rules.sqlite3")
        self.rule_db.seed_defaults()
        for p in self.config.user_blacklist_regex:
            self.rule_db.add_rule(p, "user custom rule")

        self.manifest: PackManifest | None = None
        self.current_java_bin: Path | None = None
        self.current_java_version: int = 21
        self.jvm_xmx = self.config.memory.xmx
        self.jvm_xms = self.config.memory.xms
        self.extra_jvm_flags = list(
            dict.fromkeys([
                *get_jvm_params_for_java_version(self.current_java_version),
                *self.config.extra_jvm_flags,
            ])
        )
        self.operations: list[str] = []
        self.removed_mods: list[str] = []
        self.last_ai_result: AIResult | None = None
        self.used_server_pack: bool = False
        self.attempts_used: int = 0
        self.run_success: bool = False
        self.stop_reason: str = ""

    # 文件与mods操作
    def list_mods(self) -> list[str]:
        mods_dir = self.workdirs.server / "mods"
        if not mods_dir.exists():
            return []
        return sorted([p.name for p in mods_dir.glob("*.jar") if p.is_file()])

    def remove_mods_by_name(self, names: list[str]):
        mods_dir = self.workdirs.server / "mods"
        for n in names:
            target = mods_dir / n
            if target.exists():
                target.unlink()
                self.removed_mods.append(n)
                self.operations.append(f"remove_mod_by_name:{n}")

    def remove_mods_by_regex(self, patterns: list[str]):
        mods = self.list_mods()
        for pat in patterns:
            cre = re.compile(pat)
            matched = [m for m in mods if cre.search(m)]
            self.remove_mods_by_name(matched)

    def add_remove_regex(self, pattern: str, desc: str = ""):
        self.rule_db.add_rule(pattern, desc)
        self.operations.append(f"add_remove_regex:{pattern}")

    def apply_known_client_blacklist(self):
        patterns = self.rule_db.list_rules()
        self.remove_mods_by_regex(patterns)

    def backup_mods(self, tag: str):
        mods_dir = self.workdirs.server / "mods"
        if mods_dir.exists():
            backup_directory(mods_dir, self.workdirs.backups, f"mods_{tag}")
            self.operations.append(f"backup_mods:{tag}")

    def rollback_mods(self, tag: str):
        src = self.workdirs.backups / f"mods_{tag}"
        dst = self.workdirs.server / "mods"
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            self.operations.append(f"rollback_mods:{tag}")

    # 系统与JVM
    def get_system_memory(self) -> float:
        mem = psutil.virtual_memory().total
        return round(mem / 1024 / 1024 / 1024, 2)

    def set_jvm_args(self, xmx: str, xms: str | None = None, extra_flags: list[str] | None = None):
        self.jvm_xmx = xmx
        if xms:
            self.jvm_xms = xms
        if extra_flags is not None:
            self.extra_jvm_flags = extra_flags
        self._write_start_script()
        self.operations.append(f"set_jvm_args:Xmx={self.jvm_xmx},Xms={self.jvm_xms}")

    def switch_java_version(self, version: int):
        if version not in SUPPORTED_JAVA_VERSIONS:
            raise ValueError(f"不支持的 Java 版本: {version}, 支持: {SUPPORTED_JAVA_VERSIONS}")
        java_home = self.workdirs.java_bins / f"jdk-{version}"
        bin_name = "java.exe" if os.name == "nt" else "java"
        java_bin = java_home / "bin" / bin_name
        if not java_bin.exists():
            if version in (8, 11):
                ok = self._download_dragonwell_from_github(version)
                if ok:
                    java_bin = self.workdirs.java_bins / f"jdk-{version}" / "bin" / bin_name
            if not java_bin.exists():
                raise FileNotFoundError(f"Java {version} 不存在: {java_bin}")
        self.current_java_bin = java_bin
        self.current_java_version = version
        self.extra_jvm_flags = list(
            dict.fromkeys([
                *get_jvm_params_for_java_version(version),
                *self.config.extra_jvm_flags,
            ])
        )
        self._write_start_script()
        self.operations.append(f"switch_java_version:{version}")

    def detect_current_java_version(self) -> int:
        cmd = [str(self.current_java_bin or "java"), "-version"]
        cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
        text = cp.stderr + cp.stdout
        m = re.search(r'"(\d+)(?:\.(\d+))?.*"', text)
        if not m:
            return 0
        major = int(m.group(1))
        if major == 1 and m.group(2):
            return int(m.group(2))
        return major

    # 运行与日志
    def start_server(self, timeout: int = 300) -> dict:
        script = self._start_script_path()
        if not script.exists():
            self._write_start_script()

        latest_log = self.workdirs.server / "logs" / "latest.log"
        latest_log.parent.mkdir(parents=True, exist_ok=True)
        cp = subprocess.run(
            [str(script)] if os.name != "nt" else ["cmd", "/c", str(script)],
            cwd=self.workdirs.server,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
        done = False
        if latest_log.exists():
            tail = "\n".join(latest_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-300:])
            done = "Done" in tail
        result = StartResult(
            success=(cp.returncode == 0 and done),
            done_detected=done,
            exit_code=cp.returncode,
            log_path=latest_log,
            crash_dir=self.workdirs.server / "crash-reports",
            stdout_tail="\n".join(cp.stdout.splitlines()[-80:]),
            stderr_tail="\n".join(cp.stderr.splitlines()[-80:]),
        )
        self.operations.append(f"start_server:exit={cp.returncode},done={done}")
        return asdict(result)

    def extract_relevant_log(self, log_path: str, crash_dir: str) -> dict:
        crash_path = Path(crash_dir)
        key_exception = ""
        suspected_mods: list[str] = []
        has_crash = False
        crash_content = ""

        if crash_path.exists():
            crashes = sorted(crash_path.glob("crash-*.txt"), key=lambda p: p.stat().st_mtime)
            if crashes:
                has_crash = True
                crash_content = crashes[-1].read_text(encoding="utf-8", errors="ignore")
                m = re.search(r"(?m)^\s*Caused by:\s*([^\n]+)", crash_content)
                key_exception = m.group(1).strip() if m else ""
                suspected_mods = re.findall(r"(?i)(?:mod|mods?)\s*[:=]\s*([A-Za-z0-9_\-\.]+)", crash_content)

        log = Path(log_path)
        refined = ""
        if log.exists():
            lines = log.read_text(encoding="utf-8", errors="ignore").splitlines()
            trigger = [
                "Exception",
                "Error",
                "Crash",
                "at net.minecraft",
                "java.lang.",
                "Caused by",
                "Mod Loading has failed",
                "The game crashed",
            ]
            idx = -1
            for i in range(len(lines) - 1, -1, -1):
                if any(t in lines[i] for t in trigger):
                    idx = i
                    break
            if idx != -1:
                start = max(0, idx - 100)
                refined_lines = lines[start:]
            else:
                refined_lines = lines[-500:]
            refined = "\n".join(refined_lines[-2000:])

        if not key_exception:
            m = re.search(r"(?m)([A-Za-z0-9_.]+(?:Exception|Error))", refined)
            key_exception = m.group(1) if m else "unknown"

        return {
            "has_crash": has_crash,
            "crash_content": crash_content,
            "refined_log": refined,
            "key_exception": key_exception,
            "suspected_mods": sorted(set(suspected_mods))[:20],
        }

    def analyze_with_ai(self, context: dict) -> dict:
        if not self.config.ai.enabled:
            result = AIResult(
                primary_issue="other",
                confidence=0.2,
                reason="AI未启用，返回保守策略",
                actions=[AIAction(type="stop_and_report", final_reason="AI disabled")],
            )
            self.last_ai_result = result
            return {
                "primary_issue": result.primary_issue,
                "confidence": result.confidence,
                "reason": result.reason,
                "actions": [a.__dict__ for a in result.actions],
            }

        prompt = self._build_prompt(context)
        payload = {
            "model": self.config.ai.model,
            "prompt": prompt,
            "stream": False,
        }
        resp = requests.post(self.config.ai.endpoint, json=payload, timeout=90)
        resp.raise_for_status()
        text = resp.json().get("response", "{}")
        data = json.loads(text)
        actions = [AIAction(**a) for a in data.get("actions", [])]
        result = AIResult(
            primary_issue=data.get("primary_issue", "other"),
            confidence=float(data.get("confidence", 0)),
            reason=data.get("reason", ""),
            actions=actions,
        )
        self.last_ai_result = result
        return {
            "primary_issue": result.primary_issue,
            "confidence": result.confidence,
            "reason": result.reason,
            "actions": [a.__dict__ for a in result.actions],
        }

    # 输出
    def generate_report(self) -> str:
        report_path = self.workdirs.root / "report.txt"
        ai_summary = "none"
        if self.last_ai_result:
            ai_summary = (
                f"issue={self.last_ai_result.primary_issue}, "
                f"confidence={self.last_ai_result.confidence:.2f}, "
                f"reason={self.last_ai_result.reason}"
            )
        lines = [
            "MC Auto Server Builder 报告",
            f"生成时间: {datetime.now().isoformat()}",
            f"工作目录: {self.workdirs.root}",
            f"是否成功启动: {self.run_success}",
            f"实际尝试次数: {self.attempts_used}",
            f"是否使用Server Pack优先策略: {self.used_server_pack}",
            f"清理/删除Mods数量: {len(self.removed_mods)}",
            "删除列表:",
            *[f"- {m}" for m in self.removed_mods],
            f"最终JVM: Xmx={self.jvm_xmx}, Xms={self.jvm_xms}",
            f"Java版本: {self.detect_current_java_version()}",
            f"最后一次AI结论: {ai_summary}",
            f"终止原因: {self.stop_reason or 'success_or_attempt_limit'}",
            f"总操作数: {len(self.operations)}",
            "操作记录:",
            *[f"- {x}" for x in self.operations],
        ]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return str(report_path)

    def package_server(self) -> str:
        out = self.workdirs.root / "server_pack.zip"
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in self.workdirs.server.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(self.workdirs.server))
            for p in self.workdirs.java_bins.rglob("*"):
                if p.is_file():
                    zf.write(p, Path("java_bins") / p.relative_to(self.workdirs.java_bins))
        return str(out)

    # 主流程
    def run(self) -> dict:
        self._resolve_pack_and_manifest()
        self._prepare_server_files()
        self.apply_known_client_blacklist()
        self.backup_mods("initial_copy")

        success = False
        for i in range(1, self.config.runtime.max_attempts + 1):
            self.attempts_used = i
            self.backup_mods(f"attempt_{i}")
            start_res = self.start_server(timeout=self.config.runtime.start_timeout)
            if start_res["success"]:
                success = True
                self.stop_reason = "server_done_detected"
                break
            log_info = self.extract_relevant_log(str(start_res["log_path"]), str(start_res["crash_dir"]))
            ai_context = {
                "mc_version": self.manifest.mc_version if self.manifest else "unknown",
                "loader": self.manifest.loader if self.manifest else "unknown",
                "jvm_args": f"Xmx={self.jvm_xmx} Xms={self.jvm_xms}",
                "available_ram": self.get_system_memory(),
                "mod_count": len(self.list_mods()),
                "recent_actions": self.operations[-20:],
                **log_info,
            }
            ai = self.analyze_with_ai(ai_context)
            should_stop = self._apply_actions(ai.get("actions", []))
            if should_stop:
                break

        self.run_success = success
        if not success and not self.stop_reason:
            self.stop_reason = "attempt_limit_reached"

        self._ensure_server_meta_files()
        report = self.generate_report()
        package = self.package_server()
        return {
            "success": success,
            "workdir": str(self.workdirs.root),
            "report": report,
            "package": package,
        }

    def _resolve_pack_and_manifest(self) -> None:
        if self.pack_input.input_type == "local_zip":
            zip_path = Path(self.pack_input.source)
        elif self.pack_input.input_type == "curseforge":
            zip_path = self._download_curseforge_pack(
                project_id=self.pack_input.source,
                file_id=self.pack_input.file_id,
            )
        elif self.pack_input.input_type == "modrinth":
            zip_path = self._download_modrinth_pack(
                project_or_slug=self.pack_input.source,
                version_id=self.pack_input.file_id,
            )
        elif self.pack_input.input_type == "url":
            zip_path = self._download_file(self.pack_input.source, self.workdirs.root / "pack.zip")
        else:
            raise NotImplementedError("不支持的输入类型")

        try:
            self.manifest = parse_manifest_from_zip(zip_path)
            self.operations.append(f"parse_manifest:{self.manifest.pack_name}")
        except ValueError:
            if self._zip_looks_like_server_pack(zip_path):
                self.used_server_pack = True
                self.manifest = PackManifest(
                    pack_name=zip_path.stem,
                    mc_version="unknown",
                    loader="unknown",
                    loader_version=None,
                    mods=[],
                    raw={"kind": "server_pack"},
                )
                self.operations.append(f"server_pack_detected_from_zip:{zip_path.name}")
            else:
                raise

    def _prepare_server_files(self) -> None:
        assert self.pack_input
        source_zip = Path(self.pack_input.source) if self.pack_input.input_type == "local_zip" else (self.workdirs.root / "pack.zip")
        with zipfile.ZipFile(source_zip, "r") as zf:
            zf.extractall(self.workdirs.client_temp)

        if self._copy_server_pack_if_present():
            self.used_server_pack = True
            if not self._start_script_path().exists():
                self._write_start_script()
            self.operations.append("prepare_server_files:server_pack_priority")
            return

        self._ensure_curseforge_manifest_mods()
        self._ensure_modrinth_manifest_mods()

        # 黑名单复制策略：默认复制绝大多数文件，仅排除明显客户端专用内容
        # 这样即使会多带一些无关文件，也能尽量避免漏掉服务端关键文件。
        blacklist = {
            "assets",
            "screenshots",
            "shaderpacks",
            "resourcepacks",
            "saves",
            "logs",
            "crash-reports",
            ".minecraft",
            "launcher_profiles.json",
            "options.txt",
            "optionsof.txt",
            "servers.dat",
            "usercache.json",
            "usernamecache.json",
            "manifest.json",
            "modrinth.index.json",
        }
        copied, skipped = self._copy_client_files_with_blacklist(blacklist)
        self.operations.append(f"prepare_server_files:blacklist_copy:copied={copied},skipped={skipped}")

        self._install_server_core()
        self._download_recommended_java()
        self._write_start_script()

    def _download_curseforge_pack(self, project_id: str, file_id: str | None = None) -> Path:
        out = self.workdirs.root / "pack.zip"
        resolved_project_id = self._resolve_curseforge_project_id(project_id)

        if file_id:
            file_data = self._cf_get_json(f"/v1/mods/{resolved_project_id}/files/{file_id}").get("data") or {}
            if not file_data:
                raise ValueError(f"CurseForge 文件不存在: project={resolved_project_id}, file={file_id}")
            file_name = str(file_data.get("fileName", ""))
            self.operations.append(f"curseforge_selected_file:project={resolved_project_id},file={file_id},name={file_name}")
        else:
            files = self._cf_get_json(f"/v1/mods/{resolved_project_id}/files", params={"pageSize": 50, "index": 0}).get("data") or []
            if not files:
                raise ValueError(f"CurseForge 项目没有可用文件: {resolved_project_id}")

            selected = self._pick_curseforge_server_file(files) or self._pick_curseforge_client_file(files)
            if not selected:
                raise ValueError(f"CurseForge 项目无法选择可下载文件: {resolved_project_id}")

            file_data = selected
            file_id_val = file_data.get("id")
            file_name = str(file_data.get("fileName", ""))
            self.operations.append(f"curseforge_selected_file_auto:project={resolved_project_id},file={file_id_val},name={file_name}")

        url = file_data.get("downloadUrl") or self._build_curseforge_edge_download_url(file_data)
        if not url:
            raise ValueError(f"CurseForge 文件缺少下载地址: project={resolved_project_id}, file={file_data.get('id')}")

        self._download_file(str(url), out)
        self.operations.append(f"curseforge_download_pack:{resolved_project_id}:{file_data.get('id')}")
        return out

    def _ensure_curseforge_manifest_mods(self) -> None:
        if not self.manifest:
            return
        if "files" not in self.manifest.raw:
            return

        files = self.manifest.raw.get("files") or []
        if not files:
            return

        if not (self.config.curseforge_api_key or "").strip():
            self.operations.append("curseforge_manifest_fill_skipped:no_api_key")
            return

        mods_dir = self.workdirs.client_temp / "overrides" / "mods"
        mods_dir.mkdir(parents=True, exist_ok=True)

        missing = 0
        downloaded = 0
        skipped_existing = 0

        for mod in files:
            project_id = mod.get("projectID")
            file_id = mod.get("fileID")
            if project_id is None or file_id is None:
                continue

            data = self._cf_get_json(f"/v1/mods/{project_id}/files/{file_id}").get("data") or {}
            if not data:
                continue

            file_name = str(data.get("fileName") or f"cf-{project_id}-{file_id}.jar")
            dst = mods_dir / file_name
            if dst.exists() and dst.stat().st_size > 0:
                skipped_existing += 1
                continue

            missing += 1
            url = data.get("downloadUrl") or self._build_curseforge_edge_download_url(data)
            if not url:
                self.operations.append(f"curseforge_mod_no_url:{project_id}:{file_id}")
                continue

            self._download_file(str(url), dst)
            downloaded += 1

        self.operations.append(
            f"curseforge_manifest_fill:missing={missing},downloaded={downloaded},existing={skipped_existing}"
        )

    def _resolve_curseforge_project_id(self, source: str) -> str:
        if source.isdigit():
            return source

        resp = self._cf_get_json("/v1/mods/search", params={"gameId": 432, "classId": 4471, "slug": source})
        data = resp.get("data") or []
        if not data:
            raise ValueError(f"CurseForge 未找到整合包项目: {source}")
        project_id = data[0].get("id")
        if project_id is None:
            raise ValueError(f"CurseForge 返回结果缺少项目ID: {source}")
        self.operations.append(f"curseforge_resolve_project_slug:{source}->{project_id}")
        return str(project_id)

    def _download_modrinth_pack(self, project_or_slug: str, version_id: str | None = None) -> Path:
        out = self.workdirs.root / "pack.zip"

        project = self._mr_get_json(f"/v2/project/{project_or_slug}")
        resolved_project_id = str(project.get("id") or project_or_slug)
        project_slug = str(project.get("slug") or project_or_slug)

        if version_id:
            version = self._mr_get_json(f"/v2/version/{version_id}")
            self.operations.append(
                f"modrinth_selected_version:project={resolved_project_id},version={version.get('id')},manual=true"
            )
        else:
            versions = self._mr_get_json(f"/v2/project/{project_or_slug}/version")
            if not isinstance(versions, list) or not versions:
                raise ValueError(f"Modrinth 项目没有可用版本: {project_or_slug}")

            selected = self._pick_modrinth_server_version(versions)
            if selected:
                self.operations.append(
                    f"modrinth_selected_version_auto:project={resolved_project_id},version={selected.get('id')},prefer=server"
                )
            else:
                selected = self._pick_modrinth_client_version(versions)
                if not selected:
                    raise ValueError(f"Modrinth 项目无法选择可下载版本: {project_or_slug}")
                self.operations.append(
                    f"modrinth_selected_version_auto:project={resolved_project_id},version={selected.get('id')},prefer=client"
                )

            version = selected

        file_data = self._pick_modrinth_primary_pack_file(version.get("files") or [], prefer_server=True)
        if not file_data:
            file_data = self._pick_modrinth_primary_pack_file(version.get("files") or [], prefer_server=False)
        if not file_data:
            raise ValueError(
                f"Modrinth 版本缺少可下载整合包文件: project={resolved_project_id}, version={version.get('id')}"
            )

        url = str(file_data.get("url") or "")
        if not url:
            raise ValueError(f"Modrinth 文件缺少下载地址: project={resolved_project_id}, version={version.get('id')}")

        self._download_file(url, out)
        self.operations.append(
            "modrinth_download_pack:"
            f"project={resolved_project_id},slug={project_slug},version={version.get('id')},file={file_data.get('filename')}"
        )
        return out

    def _ensure_modrinth_manifest_mods(self) -> None:
        if not self.manifest:
            return
        files = self.manifest.raw.get("files") or []
        if not isinstance(files, list) or not files:
            return

        downloaded = 0
        skipped_existing = 0
        failed = 0

        for item in files:
            rel_path = str(item.get("path") or "").strip()
            if not rel_path:
                continue

            dst = self.workdirs.client_temp / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)

            if dst.exists() and dst.stat().st_size > 0:
                skipped_existing += 1
                continue

            downloads = [str(x) for x in (item.get("downloads") or []) if str(x).startswith("http")]
            if not downloads:
                failed += 1
                self.operations.append(f"modrinth_manifest_fill_no_url:{rel_path}")
                continue

            hashes = item.get("hashes") or {}
            ok = False
            last_error = ""

            for url in downloads:
                try:
                    self._download_file(url, dst)
                    if not self._verify_modrinth_file_hash(dst, hashes):
                        last_error = "hash_mismatch"
                        if dst.exists():
                            dst.unlink()
                        continue
                    ok = True
                    downloaded += 1
                    break
                except Exception as e:
                    last_error = type(e).__name__
                    if dst.exists():
                        dst.unlink()

            if not ok:
                failed += 1
                self.operations.append(f"modrinth_manifest_fill_failed:{rel_path}:{last_error or 'unknown'}")

        self.operations.append(
            f"modrinth_manifest_fill:downloaded={downloaded},existing={skipped_existing},failed={failed}"
        )

    def _verify_modrinth_file_hash(self, file_path: Path, hashes: dict) -> bool:
        if not hashes:
            return True

        # 优先 sha512，其次 sha1
        for algo in ("sha512", "sha1"):
            expected = str(hashes.get(algo) or "").strip().lower()
            if not expected:
                continue
            h = hashlib.new(algo)
            with file_path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 256), b""):
                    h.update(chunk)
            return h.hexdigest().lower() == expected

        return True

    def _mr_get_json(self, path: str, params: dict | None = None):
        base = "https://api.modrinth.com"
        headers = {
            "Accept": "application/json",
            "User-Agent": (self.config.modrinth_user_agent or "brokestar/mc-auto-server-builder").strip(),
        }
        token = (self.config.modrinth_api_token or "").strip()
        if token:
            headers["Authorization"] = token

        resp = requests.get(f"{base}{path}", headers=headers, params=params or None, timeout=60)
        resp.raise_for_status()
        return resp.json()

    def _pick_modrinth_server_version(self, versions: list[dict]) -> dict | None:
        keywords = (
            "server",
            "serverpack",
            "server pack",
            "server files",
            "server-files",
            "服务端",
        )
        candidates: list[tuple[int, str, dict]] = []

        for v in versions:
            text = " ".join(
                [
                    str(v.get("name", "")),
                    str(v.get("version_number", "")),
                    str(v.get("version_type", "")),
                    str(v.get("changelog", ""))[:500],
                ]
            ).lower()
            files = v.get("files") or []
            score = 0

            if any(k in text for k in keywords):
                score += 8

            if v.get("version_type") == "release":
                score += 2

            for f in files:
                fname = str(f.get("filename", "")).lower()
                ftype = str(f.get("file_type", "")).lower()
                if any(k in fname or k in ftype for k in keywords):
                    score += 6
                if fname.endswith((".mrpack", ".zip")):
                    score += 2
                if bool(f.get("primary")):
                    score += 1

            if score <= 0:
                continue

            published = str(v.get("date_published", ""))
            candidates.append((score, published, v))

        if not candidates:
            return None
        return sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0][2]

    def _pick_modrinth_client_version(self, versions: list[dict]) -> dict | None:
        candidates: list[tuple[int, str, dict]] = []
        for v in versions:
            files = v.get("files") or []
            if not files:
                continue

            pack_like = 0
            for f in files:
                fname = str(f.get("filename", "")).lower()
                if fname.endswith((".mrpack", ".zip")):
                    pack_like += 1
                if bool(f.get("primary")):
                    pack_like += 1

            if pack_like <= 0:
                continue

            published = str(v.get("date_published", ""))
            release_bonus = 1 if v.get("version_type") == "release" else 0
            candidates.append((pack_like + release_bonus, published, v))

        if not candidates:
            return None
        return sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0][2]

    def _pick_modrinth_primary_pack_file(self, files: list[dict], prefer_server: bool) -> dict | None:
        if not files:
            return None

        keywords = ("server", "serverpack", "server pack", "server files", "server-files", "服务端")
        candidates: list[tuple[int, dict]] = []

        for f in files:
            name = str(f.get("filename", "")).lower()
            if not name.endswith((".mrpack", ".zip")):
                continue

            score = 0
            if bool(f.get("primary")):
                score += 4
            if prefer_server and any(k in name for k in keywords):
                score += 6
            if name.endswith(".mrpack"):
                score += 2
            candidates.append((score, f))

        if not candidates:
            return None
        return sorted(candidates, key=lambda x: x[0], reverse=True)[0][1]

    def _cf_get_json(self, path: str, params: dict | None = None) -> dict:
        api_key = (self.config.curseforge_api_key or "").strip()
        if not api_key:
            raise ValueError("CurseForge 需要配置 curseforge_api_key 才能下载整合包或补全模组")

        headers = {
            "Accept": "application/json",
            "x-api-key": api_key,
        }
        resp = requests.get(f"https://api.curseforge.com{path}", headers=headers, params=params or None, timeout=60)
        resp.raise_for_status()
        return resp.json()

    def _pick_curseforge_server_file(self, files: list[dict]) -> dict | None:
        keywords = ("server", "serverpack", "server pack", "server files", "serverfiles", "服务端")
        candidates: list[dict] = []
        for f in files:
            name = str(f.get("fileName", "")).lower()
            display = str(f.get("displayName", "")).lower()
            text = f"{name} {display}"
            if any(k in text for k in keywords):
                candidates.append(f)
        if not candidates:
            return None
        return sorted(candidates, key=lambda x: str(x.get("fileDate", "")), reverse=True)[0]

    def _pick_curseforge_client_file(self, files: list[dict]) -> dict | None:
        zip_files = [f for f in files if str(f.get("fileName", "")).lower().endswith(".zip")]
        if not zip_files:
            return None
        return sorted(zip_files, key=lambda x: str(x.get("fileDate", "")), reverse=True)[0]

    def _build_curseforge_edge_download_url(self, file_data: dict) -> str | None:
        file_id = file_data.get("id")
        file_name = file_data.get("fileName")
        if file_id is None or not file_name:
            return None
        num = int(file_id)
        return f"https://edge.forgecdn.net/files/{num // 1000}/{num % 1000:03d}/{file_name}"

    def _copy_client_files_with_blacklist(self, blacklist: set[str]) -> tuple[int, int]:
        copied = 0
        skipped = 0

        roots: list[Path] = []
        base = self.workdirs.client_temp
        roots.append(base)

        # 常见整合包结构：实际覆盖文件位于 overrides/
        overrides = base / "overrides"
        if overrides.exists() and overrides.is_dir():
            roots.append(overrides)

        # 一些压缩包会再包一层根目录，兜底纳入扫描
        top_dirs = [p for p in base.iterdir() if p.is_dir()]
        if len(top_dirs) == 1:
            nested_root = top_dirs[0]
            if nested_root.name.lower() not in {"overrides", "server", "serverfiles", "server-files", "serverpack", "server_pack"}:
                roots.append(nested_root)
                nested_overrides = nested_root / "overrides"
                if nested_overrides.exists() and nested_overrides.is_dir():
                    roots.append(nested_overrides)

        # 去重保持顺序
        dedup_roots: list[Path] = []
        seen: set[Path] = set()
        for r in roots:
            if r not in seen and r.exists() and r.is_dir():
                dedup_roots.append(r)
                seen.add(r)

        for root in dedup_roots:
            for src in root.iterdir():
                name_lc = src.name.lower()

                # 不把 overrides 目录本身作为一层目录复制，而是复制其内容
                if root == base and name_lc == "overrides":
                    skipped += 1
                    continue
                if name_lc in blacklist:
                    skipped += 1
                    continue

                dst = self.workdirs.server / src.name
                if dst.exists():
                    if dst.is_dir():
                        shutil.rmtree(dst)
                    else:
                        dst.unlink()

                if src.is_dir():
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
                copied += 1

        return copied, skipped

    def _install_server_core(self) -> None:
        # MVP: 仅创建占位 server.jar；真实实现需按 loader 下载 installer/server jar
        server_jar = self.workdirs.server / "server.jar"
        if not server_jar.exists():
            server_jar.write_bytes(b"")
        self.operations.append("install_server_core:mvp_placeholder")

    def _download_recommended_java(self) -> None:
        if not self.manifest:
            return
        version = 21
        try:
            mc = self.manifest.mc_version
            nums = [int(x) for x in mc.split(".") if x.isdigit()]
            minor = nums[1] if len(nums) > 1 else 18
            if minor <= 16:
                version = 8
            elif minor == 17:
                version = 17
            else:
                version = 21
        except Exception:
            version = 21

        # Dragonwell 8/11：通过 GitHub API 获取最新 Extended 版本并按架构下载
        if version in (8, 11):
            if self._download_dragonwell_from_github(version):
                self.extra_jvm_flags = list(
                    dict.fromkeys([
                        *get_jvm_params_for_java_version(version),
                        *self.config.extra_jvm_flags,
                    ])
                )
                self.operations.append(f"download_java:dragonwell_github_success_{version}")
                return

        # 其他版本或失败回退：优先使用系统 java
        fake_home = self.workdirs.java_bins / f"jdk-{version}" / "bin"
        fake_home.mkdir(parents=True, exist_ok=True)
        self.current_java_bin = Path("java")
        self.current_java_version = version
        self.extra_jvm_flags = list(
            dict.fromkeys([
                *get_jvm_params_for_java_version(version),
                *self.config.extra_jvm_flags,
            ])
        )
        self.operations.append(f"download_java:mvp_use_system_java_target_{version}")

    def _download_dragonwell_from_github(self, version: int) -> bool:
        repo = "dragonwell8" if version == 8 else "dragonwell11"
        api_url = f"https://api.github.com/repos/dragonwell-project/{repo}/releases"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.config.github_api_key:
            headers["Authorization"] = f"Bearer {self.config.github_api_key}"

        try:
            resp = requests.get(api_url, headers=headers, timeout=60)
            resp.raise_for_status()
            releases = resp.json()
        except Exception as e:
            self.operations.append(f"dragonwell_release_fetch_failed:{repo}:{type(e).__name__}")
            return False

        asset = self._pick_dragonwell_asset(releases)
        if not asset:
            self.operations.append(f"dragonwell_asset_not_found:{repo}")
            return False

        url = asset.get("browser_download_url")
        name = asset.get("name", "")
        if not url:
            self.operations.append(f"dragonwell_asset_no_url:{repo}:{name}")
            return False

        archive_path = self.workdirs.java_bins / name
        try:
            self._download_file(url, archive_path)
            java_home = self.workdirs.java_bins / f"jdk-{version}"
            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            extracted_root = self._extract_java_archive(archive_path, java_home)
            bin_name = "java.exe" if os.name == "nt" else "java"
            java_bin = extracted_root / "bin" / bin_name

            if not java_bin.exists():
                # fallback：某些压缩包可能直接解到了 java_home
                java_bin = java_home / "bin" / bin_name

            if not java_bin.exists():
                self.operations.append(f"dragonwell_java_bin_missing:{repo}:{name}")
                return False

            self.current_java_bin = java_bin
            self.current_java_version = version
            self.operations.append(f"dragonwell_selected_asset:{repo}:{name}")
            return True
        except Exception as e:
            self.operations.append(f"dragonwell_download_or_extract_failed:{repo}:{type(e).__name__}")
            return False

    def _pick_dragonwell_asset(self, releases: list[dict]) -> dict | None:
        arch_aliases = self._current_arch_aliases()
        is_windows = os.name == "nt"

        for rel in releases:
            tag_name = str(rel.get("tag_name", ""))
            rel_name = str(rel.get("name", ""))
            if "extended" not in (tag_name + " " + rel_name).lower():
                continue
            assets = rel.get("assets") or []
            chosen = self._pick_asset_by_arch(assets, arch_aliases, is_windows=is_windows)
            if chosen:
                return chosen
        return None

    def _pick_asset_by_arch(self, assets: list[dict], arch_aliases: set[str], is_windows: bool) -> dict | None:
        preferred_ext = (".zip", ".tar.gz", ".tgz") if is_windows else (".tar.gz", ".tgz", ".zip")
        candidates: list[dict] = []

        for a in assets:
            name = str(a.get("name", "")).lower()
            if not any(name.endswith(ext) for ext in preferred_ext):
                continue
            if not any(alias in name for alias in arch_aliases):
                continue
            candidates.append(a)

        if not candidates:
            return None

        def score(item: dict) -> tuple[int, int]:
            n = str(item.get("name", "")).lower()
            ext_score = 0
            for i, ext in enumerate(preferred_ext):
                if n.endswith(ext):
                    ext_score = len(preferred_ext) - i
                    break
            # 尽量优先 jdk 资产（排除 jre / test）
            role_score = 2 if "jdk" in n else 1
            if "jre" in n:
                role_score = 0
            return role_score, ext_score

        return sorted(candidates, key=score, reverse=True)[0]

    def _current_arch_aliases(self) -> set[str]:
        machine = platform.machine().lower()
        if machine in {"x86_64", "amd64"}:
            return {"x64", "x86_64", "amd64"}
        if machine in {"aarch64", "arm64"}:
            return {"aarch64", "arm64"}
        if machine in {"x86", "i386", "i686"}:
            return {"x86", "i386", "i686"}
        return {machine}

    def _extract_java_archive(self, archive_path: Path, java_home: Path) -> Path:
        name = archive_path.name.lower()
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(java_home)
        elif name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(java_home)
        else:
            raise ValueError(f"不支持的 Dragonwell 压缩格式: {archive_path.name}")

        children = [p for p in java_home.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return java_home

    def _write_start_script(self) -> None:
        script = self._start_script_path()
        flags = " ".join(self.extra_jvm_flags)
        java_bin = str(self.current_java_bin or "java")
        cmd = f'"{java_bin}" -Xms{self.jvm_xms} -Xmx{self.jvm_xmx} {flags} -jar server.jar nogui'
        if os.name == "nt":
            content = f"@echo off\n{cmd}\n"
        else:
            content = f"#!/usr/bin/env bash\nset -e\n{cmd}\n"
        script.write_text(content, encoding="utf-8")
        if os.name != "nt":
            script.chmod(0o755)

    def _start_script_path(self) -> Path:
        return self.workdirs.server / ("start.bat" if os.name == "nt" else "start.sh")

    def _build_prompt(self, context: dict) -> str:
        return (
            "你是一个专业的Minecraft服务器部署与优化助手。"
            "请根据以下结构化信息和精炼日志，判断无法正常启动的最可能原因，并给出最有效的修复建议。\n"
            f"上下文: {json.dumps(context, ensure_ascii=False)[:12000]}\n"
            "请严格输出JSON。"
        )

    def _apply_actions(self, actions: list[dict]) -> bool:
        for a in actions[:2]:
            t = a.get("type")
            if t == "remove_mods":
                targets = a.get("targets") or []
                names = [x for x in targets if not str(x).startswith("regex:")]
                regex_targets = [str(x).removeprefix("regex:") for x in targets if str(x).startswith("regex:")]
                if names:
                    self.remove_mods_by_name(names)
                if regex_targets:
                    self.remove_mods_by_regex(regex_targets)
                    for pat in regex_targets:
                        self.add_remove_regex(pat, "ai suggested")
            elif t == "adjust_memory":
                xmx = a.get("xmx", self.jvm_xmx)
                xms = a.get("xms", self.jvm_xms)
                xmx, xms = self._normalize_memory_plan(str(xmx), str(xms))
                self.set_jvm_args(xmx, xms)
            elif t == "change_java":
                version = int(a.get("version", 21))
                try:
                    self.switch_java_version(version)
                except (FileNotFoundError, ValueError):
                    self.operations.append(f"change_java_failed:{version}")
            elif t == "stop_and_report":
                self.stop_reason = str(a.get("final_reason", "stop_and_report"))
                self.operations.append(f"stop_and_report:{self.stop_reason}")
                return True
        return False

    def _ensure_server_meta_files(self) -> None:
        eula = self.workdirs.server / "eula.txt"
        eula.write_text("eula=true\n", encoding="utf-8")

        props = self.workdirs.server / "server.properties"
        if not props.exists():
            props.write_text(f"server-port={self.config.server_port}\nmotd=MC Auto Server Builder\n", encoding="utf-8")

    def _download_file(self, url: str, out: Path) -> Path:
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with out.open("wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        f.write(chunk)
        return out

    def _zip_looks_like_server_pack(self, zip_path: Path) -> bool:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = [n.strip("/") for n in zf.namelist()]
        normalized = [n.lower() for n in names]

        direct_markers = {
            "eula.txt",
            "server.properties",
            "start.sh",
            "start.bat",
            "run.sh",
            "run.bat",
        }
        if any(name in direct_markers for name in normalized):
            return True

        for name in normalized:
            if name.startswith(("serverfiles/", "server-files/", "server_pack/", "serverpack/", "server/")):
                return True
        return False

    def _copy_server_pack_if_present(self) -> bool:
        if not self.manifest and not self.used_server_pack:
            return False

        candidates = [
            self.workdirs.client_temp,
            self.workdirs.client_temp / "serverfiles",
            self.workdirs.client_temp / "server-files",
            self.workdirs.client_temp / "server_pack",
            self.workdirs.client_temp / "serverpack",
            self.workdirs.client_temp / "server",
        ]
        markers = {"eula.txt", "server.properties", "start.sh", "start.bat", "run.sh", "run.bat"}

        for c in candidates:
            if not c.exists() or not c.is_dir():
                continue
            child_names = {p.name.lower() for p in c.iterdir()}
            has_core = "mods" in child_names and (
                bool(child_names & markers)
                or (c / "libraries").exists()
                or any(p.name.lower().endswith(".jar") for p in c.iterdir() if p.is_file())
            )
            if not has_core:
                continue

            for p in c.iterdir():
                target = self.workdirs.server / p.name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                if p.is_dir():
                    shutil.copytree(p, target)
                else:
                    shutil.copy2(p, target)
            self.operations.append(f"copy_server_pack_from:{c.relative_to(self.workdirs.client_temp)}")
            return True
        return False

    def _normalize_memory_plan(self, xmx: str, xms: str) -> tuple[str, str]:
        total_gb = self.get_system_memory()
        cap_gb = max(1.0, total_gb * self.config.memory.max_ram_ratio)
        xmx_gb = min(self._parse_mem_to_gb(xmx), cap_gb)
        xms_gb = min(self._parse_mem_to_gb(xms), xmx_gb)

        xmx_norm = self._gb_to_mem_str(xmx_gb)
        xms_norm = self._gb_to_mem_str(xms_gb)
        self.operations.append(f"normalize_memory_plan:Xmx={xmx_norm},Xms={xms_norm},cap={cap_gb:.2f}G")
        return xmx_norm, xms_norm

    def _parse_mem_to_gb(self, value: str) -> float:
        text = value.strip().upper()
        m = re.match(r"^(\d+(?:\.\d+)?)([MG])$", text)
        if not m:
            return 4.0
        num = float(m.group(1))
        unit = m.group(2)
        if unit == "M":
            return max(0.25, num / 1024.0)
        return max(0.25, num)

    def _gb_to_mem_str(self, gb: float) -> str:
        value = max(0.25, gb)
        if value < 1:
            return f"{int(round(value * 1024))}M"
        return f"{int(value)}G"

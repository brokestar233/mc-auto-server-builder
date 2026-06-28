from __future__ import annotations

import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from .input_parser import parse_manifest_from_zip
from .util import merge_overrides_into_base, replace_path

if TYPE_CHECKING:
    from .builder import ServerBuilder


def prepare_runtime_environment(builder: ServerBuilder) -> None:
    builder._log("install.resolve", "解析输入与 manifest")
    builder._resolve_pack_and_manifest()

    if builder._resume_prepared_server_available():
        builder._log("install.resume", f"复用已有工作区: {builder.workdirs.root}")
        start_command_check = builder._verify_start_command_artifacts()
        if not bool(start_command_check.get("target_exists", False)):
            builder._recover_start_command_from_existing_server_artifacts(
                loader=getattr(builder.manifest, "loader", None) if builder.manifest else None,
                mc_version=getattr(builder.manifest, "mc_version", None) if builder.manifest else None,
                loader_version=getattr(builder.manifest, "loader_version", None) if builder.manifest else None,
                reason="resume_existing_server",
            )
        builder._log("install.meta", "恢复工作区后校正 eula.txt 与 server.properties")
        builder._ensure_server_meta_files()
        desired_java = builder._select_java_version_for_current_manifest()
        if desired_java != builder.current_java_version:
            builder.switch_java_version(desired_java)
        builder._persist_resume_state(prepared_server=True)
        return

    builder._log("install.prepare", "准备服务端文件")
    builder._prepare_server_files()

    builder._log("install.blacklist", "应用客户端黑名单规则")
    builder.apply_known_client_blacklist()
    builder.backup_mods("initial_copy")

    builder._log("install.meta", "首次启动前生成 eula.txt 与 server.properties")
    builder._ensure_server_meta_files()
    desired_java = builder._select_java_version_for_current_manifest()
    if desired_java != builder.current_java_version:
        builder.switch_java_version(desired_java)
    builder._persist_resume_state(prepared_server=True)


def resolve_pack_and_manifest(builder: ServerBuilder) -> None:
    if builder.pack_input.input_type == "local_zip":
        zip_path = Path(builder.pack_input.source)
        cache_key = builder._build_pack_cache_key(source_hint=str(zip_path.resolve()))
    elif builder.pack_input.input_type == "curseforge":
        zip_path = builder._download_curseforge_pack(
            project_id=builder.pack_input.source,
            file_id=builder.pack_input.file_id,
        )
    elif builder.pack_input.input_type == "modrinth":
        zip_path = builder._download_modrinth_pack(
            project_or_slug=builder.pack_input.source,
            version_id=builder.pack_input.file_id,
        )
    elif builder.pack_input.input_type == "url":
        cache_key = builder._build_pack_cache_key(source_hint=builder.pack_input.source)
        zip_path = builder._download_pack_to_cache(builder.pack_input.source, cache_key, stage="install.download.pack")
    else:
        raise NotImplementedError("不支持的输入类型")

    builder.resolved_pack_zip_path = zip_path
    if builder.pack_input.input_type == "local_zip":
        builder.pack_cache_key = cache_key
    elif not builder.pack_cache_key:
        builder.pack_cache_key = builder._build_pack_cache_key()

    cached_manifest = builder._load_manifest_from_cache(builder.pack_cache_key)
    if cached_manifest is not None:
        builder.manifest = cached_manifest
        builder.operations.append(f"manifest_cache_hit:{builder.pack_cache_key}")
    else:
        builder.manifest = parse_manifest_from_zip(zip_path)
        builder._persist_manifest_cache(builder.pack_cache_key, builder.manifest)
        builder.operations.append(f"manifest_cache_store:{builder.pack_cache_key}")
    builder.operations.append(f"parse_manifest:{builder.manifest.pack_name}")


def prepare_server_files(builder: ServerBuilder) -> None:
    assert builder.pack_input
    source_zip = builder.resolved_pack_zip_path or (
        Path(builder.pack_input.source) if builder.pack_input.input_type == "local_zip" else (builder.workdirs.root / "pack.zip")
    )
    builder._log("install.unpack", f"开始解压整合包: {source_zip}")
    with zipfile.ZipFile(source_zip, "r") as zf:
        zf.extractall(builder.workdirs.client_temp)
    builder._log("install.unpack", f"解压完成 -> {builder.workdirs.client_temp}")

    builder._extract_full_pack_version_payload_if_needed()

    merged_files, merged_dirs, removed_dirs = merge_overrides_into_base(builder.workdirs.client_temp)
    builder._log(
        "install.overrides",
        f"overrides 合并完成: merged_files={merged_files}, merged_dirs={merged_dirs}, removed_override_dirs={removed_dirs}",
    )

    builder._log("install.download", "补全 CurseForge/Modrinth 清单中的缺失文件")
    builder._ensure_curseforge_manifest_mods()
    builder._ensure_modrinth_manifest_mods()

    blacklist = {
        "assets",
        "screenshots",
        "shaderpacks",
        "resourcepacks",
        "saves",
        "logs",
        "crash-reports",
        "PCL",
        ".minecraft",
        "launcher_profiles.json",
        "options.txt",
        "optionsof.txt",
        "servers.dat",
        "usercache.json",
        "usernamecache.json",
        "manifest.json",
        "modrinth.index.json",
        "modlist.html",
    }
    copied, skipped = builder._copy_client_files_with_blacklist(blacklist)
    builder.operations.append(f"prepare_server_files:blacklist_copy:copied={copied},skipped={skipped}")
    builder._log("install.copy_server", f"客户端文件复制到服务端完成: copied={copied}, skipped={skipped}")

    builder._log("install.download", "下载推荐 Java 与安装服务端核心")
    builder._download_recommended_java()
    builder._install_server_core()
    builder._write_start_script()
    builder._log("install.finalize", "启动脚本生成完成")


def extract_full_pack_version_payload_if_needed(builder: ServerBuilder) -> None:
    if not builder.manifest:
        return
    full_pack = builder.manifest.raw.get("full_pack") if isinstance(builder.manifest.raw, dict) else None
    if not isinstance(full_pack, dict):
        return

    version_name = str(full_pack.get("version_name") or "").strip()
    version_dir = builder.workdirs.client_temp / ".minecraft" / "versions" / version_name
    if not version_name or not version_dir.exists() or not version_dir.is_dir():
        return

    copied = 0
    for child in sorted(version_dir.iterdir(), key=lambda p: p.name.lower()):
        if child.name in {f"{version_name}.jar", f"{version_name}.json"}:
            continue
        destination = builder.workdirs.client_temp / child.name
        replace_path(child, destination)
        copied += 1

    builder.operations.append(f"full_pack_extract:{version_name}:copied={copied}")
    builder._log("install.unpack", f"全量包版本目录提取完成: version={version_name}, copied={copied}")


def download_curseforge_pack(builder: ServerBuilder, project_id: str, file_id: str | None = None) -> Path:
    resolved_project_id = builder._resolve_curseforge_project_id(project_id)

    if file_id:
        file_data = builder._cf_get_json(f"/v1/mods/{resolved_project_id}/files/{file_id}").get("data") or {}
        if not file_data:
            raise ValueError(f"CurseForge 文件不存在: project={resolved_project_id}, file={file_id}")
        file_name = str(file_data.get("fileName", ""))
        builder.operations.append(f"curseforge_selected_file:project={resolved_project_id},file={file_id},name={file_name}")
    else:
        files = builder._cf_get_json(f"/v1/mods/{resolved_project_id}/files", params={"pageSize": 50, "index": 0}).get("data") or []
        if not files:
            raise ValueError(f"CurseForge 项目没有可用文件: {resolved_project_id}")

        selected = builder._pick_curseforge_pack_file(files)
        if not selected:
            raise ValueError(f"CurseForge 项目无法选择可下载文件: {resolved_project_id}")

        file_data = selected
        file_id_val = file_data.get("id")
        file_name = str(file_data.get("fileName", ""))
        builder.operations.append(
            f"curseforge_selected_file_auto:project={resolved_project_id},file={file_id_val},name={file_name},strategy=generic"
        )

    url = file_data.get("downloadUrl") or builder._build_curseforge_edge_download_url(file_data)
    if not url:
        raise ValueError(f"CurseForge 文件缺少下载地址: project={resolved_project_id}, file={file_data.get('id')}")

    builder.pack_cache_key = builder._build_pack_cache_key(
        source_hint=f"curseforge:{resolved_project_id}:{file_data.get('id') or file_id or 'latest'}"
    )
    out = builder._download_pack_to_cache(str(url), builder.pack_cache_key, stage="install.download.pack")
    builder.operations.append(f"curseforge_download_pack:{resolved_project_id}:{file_data.get('id')}")
    return out


def download_modrinth_pack(builder: ServerBuilder, project_or_slug: str, version_id: str | None = None) -> Path:
    project = builder._mr_get_json(f"/v2/project/{project_or_slug}")
    resolved_project_id = str(project.get("id") or project_or_slug)
    project_slug = str(project.get("slug") or project_or_slug)

    if version_id:
        version = builder._mr_get_json(f"/v2/version/{version_id}")
        builder.operations.append(f"modrinth_selected_version:project={resolved_project_id},version={version.get('id')},manual=true")
    else:
        versions = builder._mr_get_json(f"/v2/project/{project_or_slug}/version")
        if not isinstance(versions, list) or not versions:
            raise ValueError(f"Modrinth 项目没有可用版本: {project_or_slug}")

        selected = builder._pick_modrinth_pack_version(versions)
        if not selected:
            raise ValueError(f"Modrinth 项目无法选择可下载版本: {project_or_slug}")
        builder.operations.append(
            f"modrinth_selected_version_auto:project={resolved_project_id},version={selected.get('id')},strategy=generic"
        )
        version = selected

    file_data = builder._pick_modrinth_primary_pack_file(version.get("files") or [])
    if not file_data:
        raise ValueError(f"Modrinth 版本缺少可下载整合包文件: project={resolved_project_id}, version={version.get('id')}")

    url = str(file_data.get("url") or "")
    if not url:
        raise ValueError(f"Modrinth 文件缺少下载地址: project={resolved_project_id}, version={version.get('id')}")

    builder.pack_cache_key = builder._build_pack_cache_key(
        source_hint=f"modrinth:{resolved_project_id}:{version.get('id') or version_id or 'latest'}"
    )
    out = builder._download_pack_to_cache(url, builder.pack_cache_key, stage="install.download.pack")
    builder.operations.append(
        "modrinth_download_pack:"
        f"project={resolved_project_id},slug={project_slug},version={version.get('id')},file={file_data.get('filename')}"
    )
    return out

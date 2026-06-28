from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .defaults import get_common_jvm_params, get_jvm_params_for_java_version
from .recognition import choose_java_version, choose_latest_lts_java_version
from .util import DownloadError, extract_archive_payload_into, is_http_url

if TYPE_CHECKING:
    from .builder import ServerBuilder


def download_recommended_java(builder: ServerBuilder) -> None:
    if not builder.manifest:
        return
    version = choose_latest_lts_java_version()
    try:
        version = choose_java_version(builder.manifest)
    except Exception:
        version = choose_latest_lts_java_version()

    if builder._ensure_java_installed(version):
        builder.current_java_bin = builder._java_bin_path(version)
        builder.current_java_version = version
        builder._import_graalvm_external_packages(version)
        builder.operations.append(f"download_java:installed_target_{version}")
    else:
        builder.current_java_bin = Path("java")
        builder.current_java_version = version
        builder.operations.append(f"download_java:fallback_system_java_target_{version}")

    builder.extra_jvm_flags = list(
        dict.fromkeys(
            [
                *builder._resolve_java_params_for_version(version),
                *builder.config.extra_jvm_flags,
            ]
        )
    )


def resolve_java_params_for_version(builder: ServerBuilder, version: int) -> list[str]:
    mode = builder.java_params_mode_by_version.get(version)
    if mode == "common_only":
        return get_common_jvm_params()
    return get_jvm_params_for_java_version(version)


def java_bin_path(builder: ServerBuilder, version: int) -> Path:
    bin_name = "java.exe" if os.name == "nt" else "java"
    return builder.workdirs.java_bins / f"jdk-{version}" / "bin" / bin_name


def ensure_java_installed(builder: ServerBuilder, version: int) -> bool:
    java_bin = builder._java_bin_path(version)
    if java_bin.exists():
        if version in (17, 21, 25) and version not in builder.java_params_mode_by_version:
            builder.java_params_mode_by_version[version] = "graalvm"
        return True

    if version in (8, 11):
        if builder._download_dragonwell_from_github(version):
            builder.java_params_mode_by_version[version] = "graalvm"
            return builder._java_bin_path(version).exists()
        return False

    if version == 17:
        if builder._download_graalvm17_from_github():
            return builder._java_bin_path(version).exists()
        if builder._download_temurin_from_adoptium(version):
            builder.java_params_mode_by_version[version] = "common_only"
            builder.operations.append(f"java_params_mode_fallback_common:{version}")
            return builder._java_bin_path(version).exists()
        return False

    if version in (21, 25):
        if builder._download_graalvm_from_oracle(version):
            return builder._java_bin_path(version).exists()
        if builder._download_temurin_from_adoptium(version):
            builder.java_params_mode_by_version[version] = "common_only"
            builder.operations.append(f"java_params_mode_fallback_common:{version}")
            return builder._java_bin_path(version).exists()
        return False

    return False


def import_graalvm_external_packages(builder: ServerBuilder, version: int) -> None:
    if version not in (17, 21, 25):
        return
    items = [str(item).strip() for item in builder.config.graalvm_external_packages if str(item).strip()]
    if not items:
        return

    java_home = builder.workdirs.java_bins / f"jdk-{version}"
    if not java_home.exists():
        return

    imported = 0
    failed = 0
    ext_dir = java_home / "external_packages"
    ext_dir.mkdir(parents=True, exist_ok=True)

    for idx, item in enumerate(items, start=1):
        try:
            if is_http_url(item):
                parsed = urlparse(item)
                filename = Path(parsed.path).name or f"external-{idx}.bin"
                local_artifact = builder.workdirs.java_bins / "external_packages" / filename
                builder._download_file(item, local_artifact)
                src = local_artifact
            else:
                src = Path(item)
                if not src.is_absolute():
                    src = (builder.base_dir / src).resolve()
                if not src.exists() or not src.is_file():
                    raise FileNotFoundError(str(src))

            lower_name = src.name.lower()
            if lower_name.endswith(".zip") or lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
                extract_archive_payload_into(src, ext_dir, tag=f"pkg_{idx}")
            else:
                shutil.copy2(src, ext_dir / src.name)

            imported += 1
            builder.operations.append(f"graalvm_external_package_imported:{version}:{item}")
        except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as exc:
            from .builder import _build_remote_failure_detail

            failed += 1
            failure = _build_remote_failure_detail("external_package_import", exc)
            builder.operations.append(
                f"graalvm_external_package_import_failed:{version}:{item}:{failure.category}:{failure.exc_type or 'unknown'}"
            )

    builder.operations.append(f"graalvm_external_package_import_summary:{version}:ok={imported},failed={failed}")

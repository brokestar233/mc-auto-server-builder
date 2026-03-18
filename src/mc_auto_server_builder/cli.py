from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console

from .builder import ServerBuilder
from .config import AppConfig


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcasb",
        description="MC Auto Server Builder - Minecraft 整合包服务器自动构建工具",
    )
    parser.add_argument("source", help="本地zip / CurseForge项目ID或链接 / CurseForge项目ID:文件ID / Modrinth链接或ID")
    parser.add_argument("--config", help="JSON 配置文件路径", default=None)
    parser.add_argument("--base-dir", help="工作目录根路径", default=".")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出最终结果")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    config = AppConfig.load(args.config)
    builder = ServerBuilder(source=args.source, config=config, base_dir=args.base_dir)
    result = builder.run()

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    console = Console()
    console.print("[bold green]构建完成[/bold green]")
    console.print(f"成功状态: {result['success']}")
    console.print(f"工作目录: {result['workdir']}")
    console.print(f"报告文件: {result['report']}")
    console.print(f"打包文件: {result['package']}")


if __name__ == "__main__":
    main()

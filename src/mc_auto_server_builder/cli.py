from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from .builder import ServerBuilder
from .config import AppConfig, ConfigError, ProxyConfig


def _existing_file_path(value: str) -> str:
    path = Path(value)
    if not path.exists() or not path.is_file():
        raise argparse.ArgumentTypeError(f"文件不存在或不是普通文件: {value}")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcasb",
        description="MC Auto Server Builder - Minecraft 整合包服务器自动构建工具",
        epilog="示例: mcasb pack.zip --config ./config.json --base-dir ./workspace",
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="输入源：本地 zip / CurseForge 项目ID或链接 / CurseForge项目ID:文件ID / Modrinth 链接或ID",
    )
    parser.add_argument("--config", help="JSON 配置文件路径", default=None, type=_existing_file_path)
    parser.add_argument("--base-dir", help="工作目录根路径", default=".")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出最终结果")
    parser.add_argument("--check-config", action="store_true", help="仅校验配置文件并输出结果，不执行构建")
    parser.add_argument("--proxy", help="临时覆盖 HTTP/HTTPS/ALL 代理地址")
    parser.add_argument("--no-proxy", help="临时覆盖 no_proxy 配置")
    parser.add_argument(
        "--proxy-trust-env",
        choices=("true", "false"),
        help="临时覆盖是否信任环境变量代理",
    )
    return parser


def _apply_proxy_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    if args.proxy is None and args.no_proxy is None and args.proxy_trust_env is None:
        return config
    proxy_url = (args.proxy or "").strip()
    no_proxy = config.proxy.no_proxy if args.no_proxy is None else str(args.no_proxy).strip()
    trust_env = config.proxy.trust_env if args.proxy_trust_env is None else args.proxy_trust_env == "true"
    config.proxy = ProxyConfig(
        http=proxy_url or config.proxy.http,
        https=proxy_url or config.proxy.https,
        all=proxy_url or config.proxy.all,
        no_proxy=no_proxy,
        trust_env=trust_env,
    )
    return config


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.source and not args.check_config:
        parser.error("缺少 source 参数；如仅校验配置，请使用 --check-config --config <path>")
    if args.check_config and not args.config:
        parser.error("--check-config 需要同时提供 --config")

    try:
        config = AppConfig.load(args.config)
    except ConfigError as exc:
        parser.exit(2, f"配置错误: {exc}\n")
    config = _apply_proxy_overrides(config, args)

    if args.check_config:
        if args.json:
            print(json.dumps({"ok": True, "config": args.config, "message": "配置校验通过"}, ensure_ascii=False, indent=2))
            return
        console = Console(file=sys.stdout)
        console.print("[bold green]配置校验通过[/bold green]")
        console.print(f"配置文件: {args.config}")
        return

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

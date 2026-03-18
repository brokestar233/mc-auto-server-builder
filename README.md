# MC Auto Server Builder (MVP)

基于 [`TODO.md`](TODO.md) 从零实现的 Python 项目骨架，目标是自动化构建 Minecraft 整合包服务器。

## 当前实现范围（MVP）

- 项目结构与可执行 CLI
- 本地 ZIP 清单解析（`manifest.json` / `modrinth.index.json`）
- 工作目录自动创建（`workdir_<timestamp>`）
- 服务器目录文件准备与客户端模组黑名单清理
- 启动脚本生成、基础启动监控与日志提取
- AI 分析接口（支持关闭；默认关闭）
- 报告输出与打包导出
- 本地 ZIP 中自动识别并优先复用 Server Pack（若可识别）
- AI `adjust_memory` 动作自动按可用内存比例上限（默认 70%）收敛
- 报告补充：实际尝试次数、成功状态、终止原因、最后一次 AI 结论
- Dragonwell JDK 下载：Java 8/11 通过 GitHub API 自动选择最新 `Extended` Release 并按系统架构下载
- CurseForge 远程整合包下载：支持项目 ID / 项目链接 / `项目ID:文件ID`
- CurseForge 导入客户端包自动补全：若 ZIP 内有 `manifest.json`，可按清单补齐缺失 mod 文件
- CurseForge Server Files 优先：远程下载时优先选择包含服务端语义的文件名（如 server/serverpack）
- Modrinth 远程整合包下载：支持项目 ID / slug / 链接（含 version 链接）
- Modrinth 导入包补全：若 ZIP 内有 `modrinth.index.json`，会按 `files[].path + downloads + hashes` 自动补齐缺失文件并校验哈希
- Modrinth 版本选择策略：优先服务端语义版本/文件（server/serverpack/server files），其次回退到常规主文件

> 说明：真实 Loader 安装仍为占位实现（MVP 限制）。CurseForge 与 Modrinth 的远程项目下载、清单缺失文件补全、服务端资源优先策略已实现。Java 下载目前已实现 Dragonwell 8/11 的 GitHub Release 自动获取。

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 使用

```bash
mcasb /path/to/modpack.zip --config example_config.json
```

CurseForge 示例：

```bash
# 项目ID（自动选择最新 server/client 可用 zip）
mcasb 123456 --config example_config.json

# 项目ID + 文件ID（精确指定）
mcasb 123456:6543210 --config example_config.json

# 项目链接（支持 slug 或 projects 数字ID）
mcasb "https://www.curseforge.com/minecraft/modpacks/all-the-mods-9" --config example_config.json
```

Modrinth 示例：

```bash
# 项目ID或slug（自动选择优先服务端版本/文件）
mcasb fabulously-optimized --config example_config.json

# 项目链接
mcasb "https://modrinth.com/modpack/fabulously-optimized" --config example_config.json

# 指定版本链接
mcasb "https://modrinth.com/modpack/fabulously-optimized/version/abc12345" --config example_config.json

# 显式前缀写法：modrinth:项目 或 modrinth:项目:版本
mcasb "modrinth:fabulously-optimized" --config example_config.json
```

JSON 输出：

```bash
mcasb /path/to/modpack.zip --config example_config.json --json
```

## 目录结构

```text
.
├── pyproject.toml
├── README.md
├── TODO.md
└── src/mc_auto_server_builder/
    ├── __init__.py
    ├── builder.py
    ├── cli.py
    ├── config.py
    ├── defaults.py
    ├── input_parser.py
    ├── models.py
    ├── rule_db.py
    └── workspace.py
```

## 核心入口

- CLI 入口：[`main()`](src/mc_auto_server_builder/cli.py:23)
- 主流程：[`ServerBuilder.run()`](src/mc_auto_server_builder/builder.py:307)

## 本轮行为说明（对齐 [`TODO.md`](TODO.md)）

- 在 [`_prepare_server_files()`](src/mc_auto_server_builder/builder.py:351) 前置了 Server Pack 优先路径：
  - 识别 ZIP 是否像 Server Pack（包含 `eula.txt` / `server.properties` / `start.sh` 等标记）
  - 若识别成功，直接复制服务端内容到 `server/` 并跳过客户端清理复制流程
- 在 [`_apply_actions()`](src/mc_auto_server_builder/builder.py:473) 中对 `adjust_memory` 增加约束：
  - 通过 [`_normalize_memory_plan()`](src/mc_auto_server_builder/builder.py:559) 将 `Xmx/Xms` 限制在 `memory.max_ram_ratio` 以内
- 在 [`generate_report()`](src/mc_auto_server_builder/builder.py:258) 增加诊断信息：
  - `是否成功启动`、`实际尝试次数`、`是否使用Server Pack优先策略`
  - `最后一次AI结论`、`终止原因`

## 配置示例

参考 [`example_config.json`](example_config.json)。

- `github_api_key`：用于 GitHub API 鉴权（可选）
  - 为空字符串时，请求不携带 `Authorization` 头
  - 设置后，请求携带 `Authorization: Bearer <key>` 头
- `curseforge_api_key`：用于 CurseForge API 下载整合包与补全缺失 mods（建议配置）
  - 为空字符串时：
    - 远程 CurseForge 项目下载会失败
    - 本地 CurseForge ZIP 的 `manifest.json` 缺失模组补全会跳过
- `modrinth_user_agent`：请求 Modrinth API 时使用的 `User-Agent`（建议填写你自己的标识）
  - Modrinth 文档要求必须提供可识别 `User-Agent`
- `modrinth_api_token`：Modrinth API Token（可选）
  - 大多数公开下载场景可不填
  - 访问私有资源或需要鉴权时可填写

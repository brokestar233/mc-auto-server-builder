服务器全自动安装工具草案
**项目名称**：MC Auto Server Builder  
**版本**：v1.0
**目标**：实现一个高度自动化、智能化、安全可靠的Minecraft模组整合包服务器一键部署工具。支持CurseForge、Modrinth主流平台整合包，自动处理客户端mod、内存分配、Java版本、JVM参数等绝大多数启动问题，通过本地小型AI模型 + 日志智能预处理实现极高成功率。

#### 整体架构概述
- **语言**：Python 3.10+
- **核心依赖**：
  - requests、zipfile、psutil、subprocess、pathlib、json、sqlite3（正则数据库）
  - 本地LLM推理框架（如Ollama、llama.cpp、MLX、Transformers + bitsandbytes），支持Qwen3.5-4B、Phi-3-mini、Gemma2-2B等小模型
  - tqdm/rich（进度条与美化日志）
- **运行环境**：所有操作在隔离的工作目录内进行
- **用户输入**：本地整合包ZIP文件路径，或CurseForge/Modrinth项目ID/链接

#### 完整功能流程

1. **输入解析与准备阶段**
   - 支持输入形式：
     - 本地 .zip 文件
     - CurseForge 项目ID / Modrinth 项目ID / 直接下载链接
   - 自动解析整合包 manifest（manifest.json / modrinth.index.json）
     - 获取 Minecraft 版本、Loader（Forge/NeoForge/Fabric/Quilt）、Mod列表
   - 创建独立工作目录 `./workdir_<timestamp>/`，包含子目录：
     - client_temp/（临时客户端解压）
     - server/（最终服务器目录）
     - backups/（mods 与配置备份）
     - logs/（运行日志）
     - java_bins/（下载的多版本Java）
     - db/（正则规则数据库）
   - **优先策略**：自动检查该整合包是否已有官方/社区 Server Pack（CurseForge “Server Files” 或 Modrinth Server Pack）。若存在，直接下载并使用，跳过后续所有清理与调试流程。

2. **服务器核心安装**
   - 根据 MC 版本 + Loader 自动下载并安装服务器端：
     - Forge/NeoForge：下载 installer.jar，运行 `--installServer`
     - Fabric/Quilt：下载 server jar 并重命名
   - 自动下载匹配的 Java（来源：Adoptium Temurin API，优先 LTS）：
     - MC ≤1.16 → Java 8
     - MC 1.17 → Java 17
     - MC 1.18+ → Java 21（或最新LTS）
     - 多版本并存，支持后续切换
   - 生成启动脚本（start.sh / start.bat），初始使用 Aikar's flags 优化模板。

3. **客户端文件智能处理与清理**
   - 将整合包解压至 client_temp 目录
    - 下载整合包中提取的mod列表到client_temp/mods
   - 选择性复制必要文件夹到 server 目录：
     - mods、config、defaultconfigs、kubejs、scripts、openloader、resourcepacks（仅服务器需要部分）
   - 清理客户端专属内容：
     - 本地正则规则数据库（SQLite/JSON），内置常见客户端mod黑名单（OptiFine、Iris、Sodium-embed、MiniMap类、REI/JEI纯客户端、InventoryHUD、DamageTilt等），匹配删除
   - 清理完成后，立即备份 mods 文件夹（tag: "initial_copy"）

4. **自动化启动与深度智能调试循环**
   - 最大尝试次数：8 次
   - 每次启动前：
     - 备份当前 mods 文件夹与启动脚本（tag: "attempt_N"）
     - 记录系统可用物理内存（psutil）
   - 启动服务器，实时监控：
     - latest.log
     - crash-reports/ 目录
     - 进程资源占用
     - 超时：300秒（可配置）
   - 若未正常启动（未出现 “Done” 或异常退出）：
     - **日志智能提取与预处理**
       1. 优先读取最新 crash-reports 文件（若存在）
          - 取时间最新的 crash-*.txt 全文（通常已精炼）
          - 正则提取主异常类型、可疑模组等结构化信息
       2. 若无 crash report，则处理 latest.log
          - 从文件末尾向前搜索崩溃关键词（"Exception"、"Error"、"Crash"、"at net.minecraft"、"java.lang."、"Caused by"、"Mod Loading has failed"、"The game crashed" 等）
          - 命中后向上追溯 80~100 行，向下至文件末尾
          - 补充最后 500 行（确保包含模组加载阶段错误）
          - 合并后控制在 1500~2000 行以内
       3. 提取结构化元数据：
          - 主异常类型
          - 可疑模组列表
          - 是否 OOM / JVM 退出码
     - 调用本地小模型进行综合分析（输入为精炼后的上下文）
   - **AI 分析 Prompt 模板**（优化后，结构化 + 精炼日志）
     ```
     你是一个专业的Minecraft服务器部署与优化助手。请根据以下结构化信息和精炼日志，判断无法正常启动的最可能原因，并给出最有效的修复建议。

     系统信息：
     - Minecraft 版本：{mc_version}
     - Loader：{loader}
     - 当前JVM参数：{jvm_args}
     - 系统可用物理内存：{available_ram} GB
     - 当前Mods数量：{mod_count}
     - 最近操作记录：{recent_actions}
     - 是否存在crash report：{has_crash}
     - 主异常类型：{key_exception}（如 NoSuchMethodError, OutOfMemoryError）
     - 可疑模组：{suspected_mods}

     精炼日志片段（崩溃相关部分）：
     {refined_log}

     Crash Report 全文（若存在）：
     {crash_content}

     请以严格JSON格式输出（无其他文字）：
     {
       "primary_issue": "client_mod|memory_allocation|memory_oom|java_version_mismatch|mod_conflict|missing_dependency|config_error|other",
       "confidence": 0.0-1.0,
       "reason": "简要原因说明",
       "actions": [ /* 最多2个行动 */ ]
     }

     actions 示例：
     - {"type": "remove_mods", "targets": ["exact-name.jar"] 或 ["regex:^client-only-.*\\.jar$"]}
     - {"type": "adjust_memory", "xmx": "6G", "xms": "4G", "reason": "..."}
     - {"type": "change_java", "version": 17}
     - {"type": "stop_and_report", "final_reason": "详细不可自动修复原因"}
     ```
   - **自动执行 AI 建议的 actions**：
     - remove_mods → 删除文件 + 添加正则到数据库
     - adjust_memory → 修改启动脚本（Xmx 不超过物理内存70%，留系统余量）
     - change_java → 切换 Java(不存在则进入下载流程)
     - stop_and_report → 终止循环，生成详细报告
   - 成功启动并达到 “Done” 状态后 → 结束循环

5. **完成与输出**
   - 生成最终优化启动脚本
   - 输出详细报告（report.txt）：
     - 清理/删除的 mod 列表（来源：内置、正则、AI建议）
     - 最终 JVM 参数与 Java 版本
     - 总尝试次数与每次操作记录
   - 压缩完整 server 文件夹为 server_pack.zip(包含java)
   - 自动同意 eula.txt，生成基础 server.properties（端口25565、可配置）
   - （可选）保持服务器运行模式

#### 供工具调用的核心函数接口

```python
class ServerBuilder:
    # 文件与mods操作
    def list_mods(self) -> list[str]
    def remove_mods_by_name(self, names: list[str])
    def remove_mods_by_regex(self, patterns: list[str])
    def add_remove_regex(self, pattern: str, desc: str = "")
    def apply_known_client_blacklist(self)
    def backup_mods(self, tag: str)
    def rollback_mods(self, tag: str)

    # 系统与JVM
    def get_system_memory(self) -> float  # GB
    def set_jvm_args(self, xmx: str, xms: str | None = None, extra_flags: list[str] | None = None)
    def switch_java_version(self, version: int)
    def detect_current_java_version(self) -> int

    # 运行与日志
    def start_server(self, timeout: int = 300) -> dict  # 返回状态、日志路径
    def extract_relevant_log(self, log_path: str, crash_dir: str) -> dict  # v3.1 新增
    def analyze_with_ai(self, context: dict) -> dict  # 调用本地模型

    # 输出
    def generate_report(self) -> str
    def package_server(self) -> str  # 返回zip路径
```

#### 额外增强功能（分阶段实现）
- 用户自定义内存上限、JVM 参数、正则黑名单
- 进度条与彩色日志输出（rich/tqdm）
- 黑名单与正则数据库可在线更新（社区共享）
- 简单 GUI 界面（后续）
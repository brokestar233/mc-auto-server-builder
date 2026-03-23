# TODO


## 1. 指标与基准

- [ ] 将“最终成功率”定义为项目主指标之一，并建立可量化压测方法
  - 建议指标：
    - 首次成功率
    - 3 次重试后成功率
    - 最终成功率
    - 识别成功率
    - 误判成功率 / 误判失败率
    - 平均构建耗时
  - 建议样本集：
    - CurseForge 热门包
    - Modrinth 热门包
    - Forge / NeoForge / Fabric / Quilt
    - 标准包 / 服务端包 / 全量客户端包 / 历史包 / 脏包

---

## 2. 测试与验证

- [ ] 为以下格式补专项测试用例
  - `manifest.json`
  - `modrinth.index.json`
  - ServerStarter yaml
  - `variables.txt`
  - 含启动脚本但无 manifest 的包
  - 含 `.minecraft` 的全量包
  - 非标准目录嵌套包

- [ ] 建立“loader × 格式 × MC 版本 × 输入源”的测试矩阵
  - 示例维度：
    - Forge / NeoForge / Fabric / Quilt
    - CurseForge / Modrinth / local zip
    - 标准包 / server pack / 非标准包 / 历史包
    - Java 8 / 11 / 17 / 21 / 25

- [ ] 建立用于和 auto-mcs 等工具对比的 benchmark 样本集
  - 输出：
    - 可复现实验清单
    - 每个包的构建结果
    - 成功率统计
    - 失败类型统计
    - 构建耗时统计

---

## 3. 后续增强功能

- [ ] 黑名单与正则数据库在线更新能力未实现

- [ ] 简单 GUI 界面未实现

- [ ] 识别规则库独立化未实现
  - 目标：
    - 将奇怪格式识别规则从实现主流程中拆分
    - 便于后续热更新、测试、压测、规则对比

- [ ] 远程规则 / 特征签名更新能力未实现
  - 可更新内容：
    - 客户端 mod 黑名单
    - 识别文件模式
    - loader / version 特征库
    - 日志失败特征库

---

## 4. 推荐推进顺序

- [ ] 先完成测试矩阵与 benchmark 基线，再推进规则热更新与规则库独立化

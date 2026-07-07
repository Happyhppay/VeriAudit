# VeriAudit 轻量版 — 三人分工方案

> 本文档是三个人独立开发的协作基础。读完后你应该清楚：你负责哪些文件、你的代码被谁调用、你可以调用别人的什么接口。

---

## 一、分工总览

```
Person A: 核心引擎    — 数据模型、Event Ledger、状态机、裁决引擎、轻量索引
Person B: 审计流水线  — 仓库解析、SAST 工具封装、静态扫描 Agent、验证 Agent、LLM Provider
Person C: 产品层      — CLI、Web Dashboard、Pipeline Orchestrator、报告生成、动态验证占位、批量扫描
```

### 依赖方向

```
A (Schema + Event Ledger + 状态机)
     │
     ├──→ B (用 A 的 Schema 定义 Finding，用 A 的 Event Ledger 记录事件)
     │
     └──→ C (用 A 的 Schema 渲染报告，用 A 的裁决结果生成最终输出)

B 和 C 不互相依赖。
C 的 Orchestrator 调用 B 的 Agent，只关心输入输出接口，不关心内部实现。
```

---

## 二、Person A：核心引擎

### 你的定位

你是地基。你写的每一个类和函数，B 和 C 都会用。**你不依赖任何人的代码**。你最需要保证的是：接口稳定、Schema 正确、状态机逻辑严谨。

### 你负责的文件

```
veriaudit/
├── core/
│   ├── __init__.py
│   ├── schema.py                 # 所有共享数据结构（~300 行）
│   ├── event_ledger.py           # append-only JSONL + SHA-256 链（~250 行）
│   ├── finding_state_machine.py  # 状态转换校验 + 执行（~120 行）
│   ├── judge_engine.py           # 8 条确定性裁决规则（~200 行）
│   ├── invariants.py             # 不变量校验（~100 行）
│   └── exceptions.py             # 自定义异常（~30 行）
├── db/
│   ├── __init__.py
│   └── index.py                  # SQLite 轻量索引（~200 行）
├── config/
│   └── default.yaml              # 默认配置（~50 行）
└── tests/
    ├── test_event_ledger.py
    ├── test_finding_state_machine.py
    ├── test_judge_engine.py
    └── test_invariants.py
```

**总代码量：约 1,250 行**

### 你的开发顺序

1. **Day 1-2**：`schema.py` — 所有数据类定义。这是合同的第一章，B 和 C 等你的这版草稿出来才能开始写代码
2. **Day 3-4**：`event_ledger.py` — 核心的事件追加、读取、投影。写完就写单元测试
3. **Day 5**：`finding_state_machine.py` — 状态转换逻辑
4. **Day 6-7**：`judge_engine.py` + `invariants.py` — 裁决规则和不变量
5. **Day 8-9**：`db/index.py` — 轻量索引（C 的 Web 需要）
6. **Day 10**：`exceptions.py` + 补全所有测试

### 关键约束

- `schema.py` 草稿必须在 Day 2 结束前发出给 B 和 C
- 所有 Finding 的状态变更必须走 `FindingStateMachine.transition()`——B 不能直接改 `finding.status`
- Event Ledger 的哈希链算法不能改。`hash = SHA256(prev_hash + canonical_json(payload) + timestamp + event_type)`
- TaskIndex 只保存任务列表、报告路径、Finding 索引字段——**状态必须以 Event Ledger 投影为准**

---

## 三、Person B：审计流水线

### 你的定位

你负责"从仓库到 Finding"的整条链路。你拿到一个 GitHub URL 或本地路径，产出结构化的 Finding 列表。你的代码被 C 的 Orchestrator 调用。你不关心 CLI、Web、报告长什么样。

### 你负责的文件

```
veriaudit/
├── repo/
│   ├── __init__.py
│   ├── parser.py                # clone / 本地目录解析 + 语言识别（~350 行）
│   └── manifest.py              # ProjectProfile 生成（~150 行）
├── tools/
│   ├── __init__.py
│   ├── base.py                  # SAST 工具基类（~80 行）
│   ├── semgrep.py               # Semgrep 封装（~200 行）
│   ├── bandit.py                # Bandit 封装（Python 专用）（~150 行）
│   ├── gitleaks.py              # Gitleaks 封装（~150 行）
│   └── llm_provider.py          # LLM 调用封装（~250 行）
├── agents/
│   ├── __init__.py
│   ├── static_scan_agent.py     # 调度 SAST 工具，产出 RAW Finding（~250 行）
│   └── verification_agent.py    # 去重 + CWE 映射 + LLM 分析（~400 行）
└── tests/
    ├── test_repo_parser.py
    ├── test_semgrep.py
    ├── test_bandit.py
    ├── test_gitleaks.py
    ├── test_llm_provider.py
    ├── test_static_scan_agent.py
    └── test_verification_agent.py
```

**总代码量：约 1,980 行**

### 你的开发顺序

1. **Day 1-2**：等 A 的 `schema.py` 草稿 → 熟悉 Schema 中的 `Finding`、`RawFinding`、`ProjectProfile`
2. **Day 3-5**：`repo/parser.py` + `repo/manifest.py` → 能 clone 仓库、识别语言、生成 ProjectProfile
3. **Day 6-8**：`tools/semgrep.py` + `tools/bandit.py` + `tools/gitleaks.py` → 三个 SAST 工具封装
4. **Day 9-10**：`tools/llm_provider.py` → LLM 调用封装
5. **Day 11-13**：`agents/static_scan_agent.py` → 调度工具，产出 RAW Finding
6. **Day 14-17**：`agents/verification_agent.py` → 这是你最复杂的模块。去重、过滤、CWE 映射、LLM 辅助分析、状态升级
7. **Day 18-20**：测试 + 调试

### 关键约束

- 所有 Finding 状态变更必须通过 A 的 `FindingStateMachine.transition()`
- 扫描完成后，每个 Finding 必须通过 `EventLedger.append()` 写入事件
- `StaticScanAgent.scan()` 产出的 Finding 状态必须是 `RAW`
- `StaticVerificationAgent.verify()` 产出的最高状态是 `VERIFIED_STATIC`——**你不能产出 `CONFIRMED_EXPLOITED`**
- LLM 分析结果放在 `Finding.llm_analysis` 字段中，作为解释和参考，不作为裁决依据
- RawFinding 是你内部使用的中间格式，不对外暴露

### 你对 A 的依赖

| 你需要用 A 的什么 | 什么时候用到 |
|------------------|------------|
| `Finding` 类 | StaticScanAgent 创建新 finding 时 |
| `FindingStatus` 枚举 | 设置和变更 finding 状态时 |
| `ProjectProfile` 类 | RepoParser 返回结果时 |
| `EventLedger.append()` | 每次产生或修改 finding 时 |
| `emit_raw_finding()` | 扫描完成时 |
| `emit_finding_promoted()` | 状态变更时 |
| `FindingStateMachine.transition()` | VerificationAgent 升级状态时 |

### 你对 C 暴露的接口

C 只会调用以下方法，你保证这些签名不变：

```python
# repo/parser.py
class RepoParser:
    def parse(self, input_path: str) -> ProjectProfile: ...

# agents/static_scan_agent.py
class StaticScanAgent:
    def scan(self, task_id: str, repo_path: str, language: str) -> List[Finding]: ...

# agents/verification_agent.py
class StaticVerificationAgent:
    def verify(self, task_id: str, findings: List[Finding], repo_path: str) -> List[Finding]: ...

# tools/llm_provider.py
class LLMProvider:
    def analyze(self, prompt: str, context: str) -> str: ...
    def analyze_finding(self, finding: Finding, project_context: str) -> dict: ...
    def generate_fix_suggestion(self, finding: Finding) -> str: ...
    def summarize(self, findings: List[Finding]) -> str: ...
```

---

## 四、Person C：产品层

### 你的定位

你是系统的"脸"。B 产出的 Finding 列表到你手上，你把它变成用户看得见、用得着的东西：命令行工具、网页界面、报告文件。你还负责把整个流程串起来（Orchestrator），以及批量扫描。

### 你负责的文件

```
veriaudit/
├── cli/
│   ├── __init__.py
│   └── main.py                      # Click CLI（~250 行）
├── web/
│   ├── __init__.py
│   ├── app.py                       # FastAPI 入口（~150 行）
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── tasks.py                 # 任务相关路由（~200 行）
│   │   └── reports.py               # 报告相关路由（~150 行）
│   ├── templates/
│   │   ├── base.html                # 基础模板（~100 行）
│   │   ├── index.html               # 任务列表页（~100 行）
│   │   ├── task_detail.html         # 任务详情页（~100 行）
│   │   └── report.html              # 报告页（~100 行）
│   └── static/
│       └── style.css                # 样式（~150 行）
├── orchestrator/
│   ├── __init__.py
│   └── pipeline.py                  # Pipeline Orchestrator（~350 行）
├── report/
│   ├── __init__.py
│   ├── generator.py                 # HTML/JSON/Markdown 报告生成（~350 行）
│   ├── evidence_packager.py         # 证据打包（~200 行）
│   └── templates/
│       ├── report.html.j2           # HTML 报告模板（~150 行）
│       └── report.md.j2             # Markdown 报告模板（~100 行）
├── dynamic/
│   ├── __init__.py
│   ├── base.py                      # 接口定义（~50 行）
│   ├── verifier.py                  # 占位实现（~50 行）
│   └── placeholders.py             # 占位工具（~50 行）
├── batch/
│   ├── __init__.py
│   └── runner.py                    # 批量扫描（~200 行）
└── tests/
    ├── test_cli.py
    ├── test_pipeline.py
    ├── test_report_generator.py
    ├── test_dynamic_placeholder.py
    └── test_web_routes.py
```

**总代码量：约 2,800 行**

### 你的开发顺序

1. **Day 1-2**：等 A 的 `schema.py` 草稿 → 搭项目骨架，确认 `AuditReport`、`Finding` 等数据结构
2. **Day 3-5**：`dynamic/base.py` + `dynamic/verifier.py` — 动态验证占位（最简单，先做完）
3. **Day 6-10**：`web/` 全部 — FastAPI app + 四个页面 + CSS
4. **Day 11-15**：`report/` 全部 — 报告生成器 + 证据打包器 + 两个 Jinja2 模板
5. **Day 16-18**：`orchestrator/pipeline.py` — 串联整条链路。这个依赖 B 的接口，等 B 的接口稳定后再写
6. **Day 19-20**：`cli/main.py` + `batch/runner.py` + 测试

### 关键约束

- `PipelineOrchestrator.run()` 是你最重要的函数。它决定了整个审计的执行顺序
- 动态验证模块目前必须返回 `NOT_IMPLEMENTED`——你不能假装做了动态验证
- 报告中"动态验证"章节必须明确显示"Not implemented in MVP"
- 初期报告不得出现 `CONFIRMED_EXPLOITED` 状态
- WebSocket 可选：如果时间不够，用轮询代替实时推送

### 你对 A 的依赖

| 你需要用 A 的什么 | 什么时候用到 |
|------------------|------------|
| `AuditReport` 类 | 报告生成、Web 接口返回 |
| `Finding` 类 | 报告详情展示 |
| `ProjectProfile` 类 | 报告项目信息展示 |
| `EventLedger.get_events()` | Pipeline 获取事件历史 |
| `EventLedger.project_finding_status()` | 报告获取 finding 最终状态 |
| `EventLedger.verify_integrity()` | 报告显示哈希链校验结果 |
| `JudgeEngine.judge()` | Pipeline 最终裁决阶段 |
| `TaskIndex` | Web 和 CLI 查询任务列表和报告路径 |

### 你对 B 的依赖

| 你需要用 B 的什么 | 什么时候用到 |
|------------------|------------|
| `RepoParser.parse()` | Pipeline 第一步 |
| `StaticScanAgent.scan()` | Pipeline 第二步 |
| `StaticVerificationAgent.verify()` | Pipeline 第三步 |
| `LLMProvider.analyze()` | 报告生成修复建议时 |
| `LLMProvider.summarize()` | 报告生成摘要时 |

---

## 五、第一周协作安排

### Day 1（全员）

- A 讲解 `schema.py` 的设计思路
- B 和 C 提出疑问和修改建议
- 三人达成一致后 A 开始写 `schema.py`

### Day 2（全员）

- A 发出 `schema.py` 草稿（至少包含 Finding、FindingStatus、AuditEvent、ProjectProfile、AuditReport）
- B 和 C 开始熟悉 Schema，搭建自己的开发环境
- 三人一起写 `tests/contract/test_schema.py`（验证 Schema 的类型一致性）

### Day 3-4

- A：写 `event_ledger.py` + 单元测试
- B：搭 Semgrep/Bandit/Gitleaks 环境，确认能在本地命令行跑通
- C：用 FastAPI 搭出 Web 骨架（一个 `/health` 端点 + 基础模板）

### Day 5（全员 30 分钟同步）

- 三人汇报进度
- 确认接口有没有需要调整的地方
- **接口冻结**：此后任何 Schema 修改需要三人同意

---

## 六、进度一览表

| 周 | A | B | C |
|----|---|---|---|
| W1 | schema.py 草稿 → Event Ledger + 测试 | 熟悉 Schema，搭建 SAST 环境 | 熟悉 Schema，搭建 Web 骨架 |
| W2 | FindingStateMachine + JudgeEngine + 测试 | RepoParser + manifest | Web 全部路由 + 四个页面 |
| W3 | invariants.py + TaskIndex + 全部测试 | Semgrep + Bandit + Gitleaks 封装 + 测试 | Report Generator + Evidence Packager |
| W4 | 配合 B 和 C 调试接口 | LLM Provider + StaticScanAgent + 测试 | Pipeline Orchestrator + Dynamic Placeholder |
| W5 | 配合 B 和 C 调试接口 | VerificationAgent + 全部测试 | CLI + Batch Runner + 测试 |
| W6 | 集成调试 + Bug 修复 | 集成调试 + Bug 修复 | 集成调试 + 模板完善 |
| W7-8 | 文档 + 善后 | 文档 + 善后 | 文档 + 善后 |

---

## 七、拼接日（预计第 6 周某一天）

### 拼前检查清单

- [ ] A：`pytest tests/ -k "event_ledger or state_machine or judge"` 全部通过
- [ ] B：`pytest tests/ -k "repo or semgrep or bandit or gitleaks or llm or agent"` 全部通过
- [ ] C：`pytest tests/ -k "cli or pipeline or report or dynamic or web"` 全部通过

### 拼接步骤

```bash
# 1. 合并代码
git merge person-a/main person-b/main person-c/main

# 2. 跑全量契约测试
pytest tests/contract/ -v
# 期望：全部通过

# 3. 准备测试 fixture
# 创建一个最小的 PHP 文件，包含已知 SQL 注入代码
mkdir -p fixtures/php-sqli-test
cat > fixtures/php-sqli-test/index.php << 'EOF'
<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysql_query($sql);
?>
EOF

# 4. 端到端冒烟测试
veriaudit audit ./fixtures/php-sqli-test --mode standard

# 期望输出:
#   [1/6] Parsing repository...
#   [2/6] Running static analysis...
#   [3/6] Verifying findings...
#   [4/6] Dynamic verification... (skipped: not implemented)
#   [5/6] Generating report...
#   [6/6] Done.
#   Report: results/<task_id>/report.html

# 5. 验证 Event Ledger 哈希链
veriaudit verify-ledger <task_id>
# 期望: "Integrity check passed (N events)"

# 6. 检查报告中没有 CONFIRMED_EXPLOITED
grep -r "CONFIRMED_EXPLOITED" results/<task_id>/ && echo "FAIL" || echo "PASS"

# 7. 打开 Web 界面检查
# 浏览器打开 http://localhost:8000
# 确认能看到任务列表、任务详情、报告
```

---

## 八、沟通规则

| 规则 | 说明 |
|------|------|
| **接口修改需三人 approve** | 任何 Schema、公开方法签名的修改，需在群内发 diff，三人回复 OK 才能合 |
| **每天一条进度** | 下班前在群里发一句话：今天完成了什么、明天做什么、有没有堵点 |
| **每周五 15 分钟同步** | 快速过一遍本周产出、下周计划、接口问题 |
| **contract 测试是安全网** | 如果你改了接口但没更新 contract 测试，CI 会挂。挂了就别合 |
| **遇到歧义先问** | 对接口理解有歧义时，先看本文档 → 再看 `INTERFACES.md` → 再问 A |

---

## 附录：文件清单

| 文件 | 责任人 | 估计行数 |
|------|--------|---------|
| `core/schema.py` | A | 300 |
| `core/event_ledger.py` | A | 250 |
| `core/finding_state_machine.py` | A | 120 |
| `core/judge_engine.py` | A | 200 |
| `core/invariants.py` | A | 100 |
| `core/exceptions.py` | A | 30 |
| `db/index.py` | A | 200 |
| `config/default.yaml` | A | 50 |
| `repo/parser.py` | B | 350 |
| `repo/manifest.py` | B | 150 |
| `tools/base.py` | B | 80 |
| `tools/semgrep.py` | B | 200 |
| `tools/bandit.py` | B | 150 |
| `tools/gitleaks.py` | B | 150 |
| `tools/llm_provider.py` | B | 250 |
| `agents/static_scan_agent.py` | B | 250 |
| `agents/verification_agent.py` | B | 400 |
| `cli/main.py` | C | 250 |
| `web/app.py` | C | 150 |
| `web/routes/tasks.py` | C | 200 |
| `web/routes/reports.py` | C | 150 |
| `web/templates/*.html` | C | 400 |
| `web/static/style.css` | C | 150 |
| `orchestrator/pipeline.py` | C | 350 |
| `report/generator.py` | C | 350 |
| `report/evidence_packager.py` | C | 200 |
| `report/templates/*.j2` | C | 250 |
| `dynamic/base.py` | C | 50 |
| `dynamic/verifier.py` | C | 50 |
| `dynamic/placeholders.py` | C | 50 |
| `batch/runner.py` | C | 200 |
| 测试文件（三人各自） | A/B/C | ~1,500 |
| **总代码量** | | **~7,500** |

# VeriAudit 接口契约文档

> **三人开发的唯一技术合同。所有接口以本文档为准。**
> 修改流程：任何修改需三人 approve，同步更新本文档和对应契约测试。

---

## 一、共享数据结构 (A 实现，三人共用)

### 1.1 Finding 状态

```python
class FindingStatus(str, Enum):
    RAW = "raw"
    CANDIDATE = "candidate"
    REJECTED_STATIC = "rejected_static"
    VERIFIED_STATIC = "verified_static"
    PENDING_DYNAMIC_VALIDATION = "pending_dynamic_validation"
    DYNAMIC_NOT_IMPLEMENTED = "dynamic_not_implemented"
    INCONCLUSIVE = "inconclusive"
    # 后续启用: CONFIRMED_EXPLOITED, UNREPRODUCIBLE, FALSE_POSITIVE

    TRANSITIONS = {
        RAW:              [CANDIDATE, REJECTED_STATIC],
        CANDIDATE:        [VERIFIED_STATIC, REJECTED_STATIC, INCONCLUSIVE],
        VERIFIED_STATIC:  [PENDING_DYNAMIC_VALIDATION],
        PENDING_DYNAMIC_VALIDATION: [DYNAMIC_NOT_IMPLEMENTED, INCONCLUSIVE],
        REJECTED_STATIC:  [],
        DYNAMIC_NOT_IMPLEMENTED: [],
        INCONCLUSIVE:     [CANDIDATE],
    }

    @classmethod
    def is_terminal(cls, status): ...
    @classmethod
    def can_transition(cls, from_, to): ...
```

### 1.2 Finding

```python
class Finding(BaseModel):
    finding_id: str                   # "F-xxxxxxxxxxxx" (12位hex)
    task_id: str                      # 审计任务 ID
    status: FindingStatus = FindingStatus.RAW
    source_tool: str                  # "semgrep" | "bandit" | "gitleaks"
    rule_id: str                      # 工具规则 ID
    file_path: str                    # 相对于仓库根目录
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    message: str                      # 工具原始消息
    severity: str = "info"            # critical | high | medium | low | info
    cwe: Optional[str] = None         # "CWE-89"
    confidence: str = "medium"        # high | medium | low
    llm_analysis: Optional[str] = None  # LLM 分析说明
    call_path: List[dict] = []        # 调用路径
    evidence: List[dict] = []         # 证据列表
    ruling: Optional[str] = None      # 最终裁决结果
    ruling_reason: Optional[str] = None
    matched_rule_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
```

### 1.3 Event Ledger 事件

```python
class AuditEvent(BaseModel):
    event_id: str                     # "evt-xxxxxxxxxxxx"
    task_id: str
    finding_id: Optional[str] = None  # 非 finding 事件可为空
    seq: int                          # 全局递增序号
    timestamp: datetime
    event_type: str                   # "repo.cloned" | "analysis.raw_finding_emitted" | ...
    payload: dict                     # 任意 JSON
    prev_hash: str                    # 前一条事件的 hash
    hash: str                         # SHA256(prev_hash + canonical_json(payload) + timestamp + event_type)

    def compute_hash(self) -> str:
        """hash = SHA256(prev_hash + canonical_json(payload) + timestamp + event_type)"""
```

**关键事件类型**：

| event_type | payload 关键字段 | 谁写 |
|-----------|-----------------|------|
| `audit.session.created` | `{repo_url, mode}` | C (Orchestrator) |
| `repo.cloned` | `{repo_url, commit_sha, repo_path}` | B (RepoParser) |
| `repo.parsed` | `{language, build_system, file_count}` | B (RepoParser) |
| `analysis.raw_finding_emitted` | `{finding_id, source_tool, rule_id, file_path, line_start}` | B (StaticScanAgent) |
| `analysis.finding_promoted` | `{finding_id, from_status, to_status, reason, agent_id}` | B (VerificationAgent) |
| `analysis.finding_rejected` | `{finding_id, reason}` | B (VerificationAgent) |
| `verification.dynamic_not_implemented` | `{finding_id, reason: "MVP limitation"}` | C (Pipeline) |
| `judge.ruling_made` | `{finding_id, ruling, matched_rule_id}` | C (Pipeline) |
| `report.generated` | `{task_id, report_paths}` | C (ReportGenerator) |
| `error.occurred` | `{error_message, stack_trace}` | 任何人 |

### 1.4 项目画像

```python
class ProjectProfile(BaseModel):
    task_id: str
    repo_url: str
    commit_sha: Optional[str] = None
    local_path: Optional[str] = None
    language: str                     # python | php | javascript | typescript | unknown
    frameworks: List[str] = []
    file_count: int = 0
    total_loc: int = 0
    dependencies: List[str] = []
    entry_points: List[dict] = []     # [{"file": "index.php", "type": "web_entry"}]
```

### 1.5 审计报告

```python
class AuditReport(BaseModel):
    task_id: str
    project: ProjectProfile
    created_at: datetime
    completed_at: Optional[datetime] = None
    status: str                       # running | completed | failed
    total_raw: int = 0
    total_candidates: int = 0
    total_verified_static: int = 0
    total_rejected_static: int = 0
    total_pending_dynamic: int = 0
    total_dynamic_not_implemented: int = 0
    total_inconclusive: int = 0
    findings: List[Finding] = []
    report_paths: dict = {}           # {"html": "...", "json": "...", "markdown": "..."}
```

### 1.6 裁决规则

```python
class JudgeRule(BaseModel):
    rule_id: str                      # "R001"
    condition: str                    # 人类可读
    verdict: FindingStatus
    confidence: float
    priority: int                     # 越小越优先
```

**默认 8 条规则**：

```python
DEFAULT_RULES = [
    JudgeRule("R001", "文件路径或代码行不存在", FindingStatus.FALSE_POSITIVE, 0.99, 1),
    JudgeRule("R002", "告警位于 vendor/test/fixture 且无业务入口", FindingStatus.REJECTED_STATIC, 0.95, 2),
    JudgeRule("R003", "参数已被安全 API 处理且 LLM 未发现绕过路径", FindingStatus.REJECTED_STATIC, 0.85, 3),
    JudgeRule("R004", "有 source→sink 静态证据但未做动态验证", FindingStatus.PENDING_DYNAMIC_VALIDATION, 0.90, 4),
    JudgeRule("R005", "只有 LLM 推理、无工具证据", FindingStatus.INCONCLUSIVE, 0.80, 5),
    JudgeRule("R006", "发现密钥但未验证有效性", FindingStatus.PENDING_DYNAMIC_VALIDATION, 0.85, 4),
    JudgeRule("R007", "Semgrep/Bandit 与 LLM 分析一致且代码位置真实", FindingStatus.VERIFIED_STATIC, 0.90, 4),
    JudgeRule("R008", "动态验证模块返回 NOT_IMPLEMENTED", FindingStatus.DYNAMIC_NOT_IMPLEMENTED, 1.0, 3),
]
```

---

## 二、Person A → Person B 接口

### 2.1 EventLedger

```python
class EventLedger:
    """B 通过 ledger 记录所有状态变更。"""

    def __init__(self, ledger_dir: str = "./workspace/ledgers"):
        """初始化，指定账本存储目录"""
        ...

    def append(self, event: AuditEvent) -> AuditEvent:
        """
        追加一条事件。自动分配 seq、自动计算 prev_hash 和 hash。
        线程安全。

        Args:
            event: 事件对象（不必填 seq/prev_hash/hash，它们会被自动填充）

        Returns:
            填充完整的事件对象

        Raises:
            LedgerWriteError: 磁盘写入失败
        """
        ...

    def get_events(self, task_id: str) -> List[AuditEvent]:
        """获取某任务的全部事件，按 seq 排序"""
        ...

    def get_finding_events(self, finding_id: str) -> List[AuditEvent]:
        """获取某个 finding 的所有事件"""
        ...

    # B 不需要调用以下方法，这里是给 C 的
    # def project_finding_status(...)
    # def project_all_findings(...)
    # def verify_integrity(...)
```

### 2.2 快捷事件方法

```python
# B 直接用这些函数写入特定类型的事件，不必每次手动构造 AuditEvent

def emit_raw_finding(ledger: EventLedger, finding: Finding) -> AuditEvent:
    """Finding 创建时调用。event_type = analysis.raw_finding_emitted"""
    ...

def emit_finding_promoted(ledger: EventLedger, finding_id: str,
                           from_status: str, to_status: str,
                           reason: str, agent_id: str) -> AuditEvent:
    """状态变更时调用。event_type = analysis.finding_promoted"""
    ...

def emit_finding_rejected(ledger: EventLedger, finding_id: str,
                           reason: str, agent_id: str) -> AuditEvent:
    """Finding 被拒绝时调用。event_type = analysis.finding_rejected"""
    ...

def emit_error(ledger: EventLedger, task_id: str,
                error_message: str) -> AuditEvent:
    """出错时调用。event_type = error.occurred"""
    ...
```

### 2.3 FindingStateMachine

```python
class FindingStateMachine:
    """B 只能通过这个类变更 Finding 状态。B 不能直接改 finding.status。"""

    def transition(self, finding: Finding, to_status: FindingStatus,
                   reason: str, ledger: EventLedger,
                   agent_id: str = "verification_agent") -> Finding:
        """
        执行状态转换。

        1. 校验 from_status → to_status 是否合法
        2. 校验 finding 是否为终态（终态不可变更）
        3. 更新 finding.status 和 finding.updated_at
        4. 写入 analysis.finding_promoted 事件
        5. 返回更新后的 finding

        Args:
            finding: 当前 finding（必须包含 finding_id, task_id, status）
            to_status: 目标状态
            reason: 变更原因
            ledger: Event Ledger 实例
            agent_id: 调用方标识

        Returns:
            更新了 status 的 finding

        Raises:
            InvalidStateTransition: from_status → to_status 不合法
            TerminalStateModification: finding 处于终态
        """
        ...

    def is_terminal(self, status: FindingStatus) -> bool: ...

    def get_allowed_transitions(self, status: FindingStatus) -> List[FindingStatus]: ...
```

---

## 三、Person A → Person C 接口

### 3.1 EventLedger（C 用的额外方法）

```python
class EventLedger:
    # ... (append, get_events 同上)

    def project_finding_status(self, finding_id: str) -> FindingStatus:
        """
        确定性投影。从事件序列计算 finding 的当前状态。
        不读数据库，只读 Event Ledger。

        算法:
            1. 过滤该 finding_id 的所有事件
            2. 按 seq 排序
            3. 应用所有 finding_promoted 和 finding_rejected 事件
            4. 返回最终状态
        """
        ...

    def project_all_findings(self, task_id: str) -> Dict[str, FindingStatus]:
        """投影某任务的所有 finding 状态。返回 {finding_id: status}"""
        ...

    def project_finding_history(self, finding_id: str) -> List[dict]:
        """
        返回 finding 的完整状态变更历史。
        [{seq, timestamp, from_status, to_status, reason}, ...]
        """
        ...

    def verify_integrity(self, task_id: str) -> dict:
        """
        验证哈希链完整性。
        Returns: {"valid": True/False, "total_events": N, "first_broken_seq": None/int}
        """
        ...
```

### 3.2 JudgeEngine

```python
class JudgeEngine:
    """C 的 Pipeline 在最后阶段调用"""

    def __init__(self, rules: Optional[List[JudgeRule]] = None):
        """默认使用 DEFAULT_RULES"""
        ...

    def judge(self, finding: Finding, events: List[AuditEvent]) -> Finding:
        """
        按规则优先级逐条匹配。
        命中则更新 finding.status / ruling / matched_rule_id。
        都没命中则标记为 INCONCLUSIVE。

        Args:
            finding: 待裁决的 finding
            events: 该 finding 的所有事件

        Returns:
            更新后的 finding（status 已更新为最终裁决结果）
        """
        ...

    def get_rules(self) -> List[JudgeRule]: ...
```

### 3.3 TaskIndex

```python
class TaskIndex:
    """
    SQLite 轻量索引。只存任务元信息和报告路径。
    状态以 Event Ledger 投影为准，不在这里存状态。
    """

    def __init__(self, db_path: str = "./workspace/index.db"): ...

    def create_task(self, task_id: str, repo_url: str,
                     mode: str, status: str = "pending") -> None: ...
    def update_task_status(self, task_id: str, status: str) -> None: ...
    def save_report(self, task_id: str, report: AuditReport) -> None: ...
    def get_task(self, task_id: str) -> Optional[dict]: ...
    def list_tasks(self, limit: int = 20, offset: int = 0) -> List[dict]:
        """返回 [{task_id, repo_url, mode, status, created_at, completed_at, report_paths}]"""
        ...
    def get_finding_summaries(self, task_id: str) -> List[dict]:
        """返回 [{finding_id, status, severity, cwe, file_path, message}]"""
        ...
```

---

## 四、Person B → Person C 接口

### 4.1 RepoParser

```python
class RepoParser:
    """
    C 的 Pipeline 第一步调用。
    输入 GitHub URL 或本地路径 → 输出 ProjectProfile。
    """

    def __init__(self, ledger: EventLedger): ...

    def parse(self, task_id: str, input_path: str) -> ProjectProfile:
        """
        Args:
            task_id: 审计任务 ID
            input_path: GitHub URL 或本地目录绝对路径

        Returns:
            ProjectProfile（含语言、框架、依赖、入口点）

        流程:
            1. 如果是 URL → git clone 到 /tmp/veriaudit/repos/<task_id>/
               记录 commit_sha
            2. 如果是本地路径 → 直接使用，commit_sha 为 None
            3. detect_language() → 统计文件扩展名，识别主语言
            4. detect_frameworks() → 检查 package.json / composer.json / requirements.txt
            5. extract_dependencies() → 解析依赖文件
            6. extract_entry_points() → 识别入口文件
            7. 写入 repo.cloned 和 repo.parsed 事件
            8. 返回 ProjectProfile

        Raises:
            RepoCloneError: git clone 失败
            InvalidRepoError: 路径无效或非代码仓库
        """
        ...
```

### 4.2 StaticScanAgent

```python
class StaticScanAgent:
    """
    C 的 Pipeline 第二步调用。
    并行运行所有适用的 SAST 工具，产出 RAW Finding 列表。
    """

    def __init__(self, tools: List[SASTTool], ledger: EventLedger): ...

    def scan(self, task_id: str, repo_path: str,
             language: str) -> List[Finding]:
        """
        Args:
            task_id: 审计任务 ID
            repo_path: 仓库本地路径
            language: B 的 RepoParser 检测出的语言 (python | php | javascript)

        Returns:
            List[Finding] where every finding.status == FindingStatus.RAW

        流程:
            1. 根据语言选择工具:
               - Python → Semgrep + Bandit + Gitleaks
               - PHP → Semgrep + Gitleaks
               - JavaScript/TypeScript → Semgrep + Gitleaks
            2. 并行运行所有工具
            3. 每个工具的每行输出包装为一个 Finding
            4. 调用 emit_raw_finding() 写入事件
            5. 返回 Finding 列表

        所有 finding 的状态必须是 RAW。
        """
        ...
```

### 4.3 StaticVerificationAgent

```python
class StaticVerificationAgent:
    """
    C 的 Pipeline 第三步调用。
    对 RAW finding 做去重、过滤、CWE 映射、LLM 辅助分析。
    """

    def __init__(self, llm: LLMProvider, ledger: EventLedger,
                 state_machine: FindingStateMachine): ...

    def verify(self, task_id: str, findings: List[Finding],
               repo_path: str) -> List[Finding]:
        """
        Args:
            task_id: 审计任务 ID
            findings: StaticScanAgent.scan() 返回的 RAW Finding 列表
            repo_path: 仓库路径

        Returns:
            更新了 status 的 Finding 列表（VERIFIED_STATIC / REJECTED_STATIC / INCONCLUSIVE）

        流程:
            1. 去重: 同文件 + 同行号(±3) + 同规则 ID → 保留置信度最高的
            2. 过滤: 位于 vendor/ test/ tests/ fixture/ 路径且确定无业务入口 → REJECTED_STATIC
            3. CWE 映射: 工具 CWE 缺失时用 LLM 补全 (放在 finding.cwe 字段)
            4. LLM 辅助分析:
               - 对每个候选 finding，调用 llm.analyze_finding()
               - LLM 返回 {explanation, is_likely_false_positive, suggested_cwe, ...}
               - 结果存入 finding.llm_analysis
            5. 没有工具证据、只有 LLM 判断的 → INCONCLUSIVE
            6. 有工具证据 + LLM 确认的 → VERIFIED_STATIC
            7. 有工具证据 + LLM 判断为误报的 → REJECTED_STATIC
            8. 对每条，调用 state_machine.transition() 变更状态
            9. 返回更新后的 Finding 列表

        重要约束:
            - 最高产出状态是 VERIFIED_STATIC
            - 绝对不能产出 CONFIRMED_EXPLOITED
            - LLM 分析只是辅助，不作为独立裁决依据
        """
        ...
```

### 4.4 LLMProvider

```python
class LLMProvider:
    """
    OpenAI-compatible 接口。B 的 VerificationAgent 和 C 的 Report 共用。
    """

    def __init__(self, config: dict):
        """
        config = {
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "sk-xxx",
            "model": "deepseek-chat",
            "temperature": 0.1,
            "max_tokens": 8000
        }
        """
        ...

    def analyze(self, system_prompt: str, user_message: str) -> str:
        """通用 LLM 调用。返回文本响应。"""
        ...

    def analyze_finding(self, finding: Finding,
                         project_context: str = "") -> dict:
        """
        分析单个 finding。LLM 给出综合判断。

        Args:
            finding: 待分析的 finding（status 为 RAW 或 CANDIDATE）
            project_context: 项目上下文描述

        Returns:
            {
                "explanation": "该 finding 是...",
                "cwe": "CWE-89",
                "severity": "high",
                "is_likely_false_positive": False,
                "false_positive_reason": "",
                "confidence": "high",
                "recommendation": "建议使用参数化查询..."
            }
        """
        ...

    def generate_fix_suggestion(self, finding: Finding) -> str:
        """为 finding 生成修复建议文本"""
        ...

    def summarize(self, findings: List[Finding]) -> str:
        """
        对一批 finding 做汇总摘要。

        Returns:
            自然语言摘要（Markdown 格式）
        """
        ...
```

---

## 五、Person C 对外接口

### 5.1 PipelineOrchestrator

```python
class PipelineOrchestrator:
    """
    硬编码状态机，串起整个审计流程。
    被 CLI 和 Web 共同调用。这是系统的唯一主入口。
    """

    def __init__(self,
                 repo_parser,            # B: RepoParser
                 static_scan_agent,      # B: StaticScanAgent
                 verification_agent,     # B: StaticVerificationAgent
                 dynamic_verifier,       # C: DynamicVerifier
                 judge_engine,           # A: JudgeEngine
                 report_generator,       # C: ReportGenerator
                 ledger,                 # A: EventLedger
                 state_machine,          # A: FindingStateMachine
                 task_index):            # A: TaskIndex
        ...

    def run(self, input_path: str, mode: str = "standard",
            task_id: Optional[str] = None) -> AuditReport:
        """
        完整审计流程的入口。CLI 和 Web 都调这个。

        Args:
            input_path: GitHub URL 或本地路径
            mode: "quick" | "standard" (deep 暂不可用)
            task_id: 可选的任务 ID，不传则自动生成

        Returns:
            AuditReport（含所有 finding 的最终状态和报告路径）

        阶段（Standard 模式）:
            1. INIT:      repo_parser.parse() → ProjectProfile
            2. STATIC:    static_scan_agent.scan() → List[Finding](RAW)
            3. VERIFY:    verification_agent.verify() → List[Finding](VERIFIED_STATIC/...)
            4. DYNAMIC:   对 VERIFIED_STATIC → state_machine.transition(PENDING_DYNAMIC)
                          → dynamic_verifier.verify() → NOT_IMPLEMENTED
                          → state_machine.transition(DYNAMIC_NOT_IMPLEMENTED)
            5. JUDGE:     judge_engine.judge() → 最终状态
            6. REPORT:    report_generator.generate() → 报告文件
            7. SAVE:      task_index.save_report()
                          ledger.append(report.generated 事件)
            8. RETURN:    AuditReport

        每个阶段完成后写入 Event Ledger。
        异常时写入 error.occurred，更新 task_index 状态为 failed。
        """
        ...

    def get_status(self, task_id: str) -> dict:
        """
        查询审计进度。Web 用这个做轮询。

        Returns:
            {
                "task_id": "...",
                "status": "running" | "completed" | "failed",
                "current_phase": "static_scan" | "verify" | ...,
                "progress_pct": 40,
                "total_findings": 317
            }
        """
        ...
```

### 5.2 DynamicVerifier（占位）

```python
class DynamicVerificationRequest(BaseModel):
    finding_id: str
    vulnerability_type: str       # "sql_injection" | "command_injection" | ...
    file_path: str
    line: Optional[int] = None
    static_evidence: dict = {}
    suggested_payloads: List[str] = []


class DynamicVerificationResult(BaseModel):
    status: str                   # MVP 始终为 "NOT_IMPLEMENTED"
    evidence_dir: Optional[str] = None
    reproducible: bool = False
    attempts: int = 0
    logs: List[str] = []


class DynamicVerifier:
    """
    初期始终返回 NOT_IMPLEMENTED。
    后续改这个类的方法来启用真实的动态验证。
    """

    def verify(self, request: DynamicVerificationRequest) -> DynamicVerificationResult:
        """始终返回 NOT_IMPLEMENTED"""
        return DynamicVerificationResult(
            status="NOT_IMPLEMENTED",
            evidence_dir=None,
            reproducible=False,
            attempts=0,
            logs=["Dynamic verification is reserved but not yet implemented in MVP."],
        )
```

### 5.3 ReportGenerator

```python
class ReportGenerator:
    def __init__(self, template_dir: str = "./veriaudit/report/templates"): ...

    def generate(self, report: AuditReport,
                 output_dir: str) -> dict:
        """
        生成三种格式的报告。
        Args:
            report: 完整的 AuditReport
            output_dir: 输出目录，如 results/<task_id>/
        Returns:
            {"html": "results/<task_id>/report.html",
             "json": "results/<task_id>/findings.json",
             "markdown": "results/<task_id>/report.md"}
        """
        ...

    def generate_html(self, report, path) -> str: ...
    def generate_json(self, report, path) -> str: ...
    def generate_markdown(self, report, path) -> str: ...
```

**报告约束**：
- 动态验证章节必须存在，但明确显示 `NOT_IMPLEMENTED`
- 所有 finding 的 status 必须从 Event Ledger 投影，不直接读数据库
- 不得显示 `CONFIRMED_EXPLOITED`（除非后续真实动态验证完成）
- 报告需包含 Event Ledger 哈希链校验结果

### 5.4 EvidencePackager

```python
class EvidencePackager:
    def package(self, finding: Finding, events: List[AuditEvent],
                output_dir: str) -> str:
        """
        为单个 finding 生成证据目录。
        Returns: 证据目录路径

        生成文件:
            evidence/<finding_id>/
            ├── finding.json          # 完整 Finding 数据
            ├── event_chain.txt       # 事件链（文本格式）
            ├── source_snippet.txt    # 代码片段
            └── llm_analysis.md       # LLM 分析结果
        """
        ...
```

### 5.5 CLI

```python
# CLI 接口约定，C 用 Click 实现

veriaudit audit <INPUT> [OPTIONS]
    INPUT: GitHub URL 或本地目录路径
    --mode [quick|standard]    默认 standard
    --output-dir PATH          默认 results/<task_id>/
    --task-id TEXT             可选，指定任务 ID

veriaudit report <TASK_ID> [OPTIONS]
    --format [html|json|markdown]  默认 html
    --output PATH

veriaudit list [OPTIONS]
    --limit INT     默认 20
    --status TEXT   筛选状态 (running/completed/failed)

veriaudit compare <TASK_ID_1> <TASK_ID_2>
    # 对比两次审计结果

veriaudit verify-ledger <TASK_ID>
    # 验证 Event Ledger 哈希链完整性
```

### 5.6 Web API

```python
# FastAPI 路由约定

# POST /api/tasks
#   提交审计任务。后台异步执行 Pipeline。
#   Request:  {"repo_url": "https://github.com/...", "mode": "standard"}
#   Response: {"task_id": "task-20260707-xxxx", "status": "pending"}

# GET /api/tasks
#   获取任务列表
#   Query:    ?limit=20&offset=0&status=completed
#   Response: [{"task_id": "...", "repo_url": "...", "status": "...", "created_at": "..."}]

# GET /api/tasks/{task_id}
#   获取任务详情 + Finding 摘要
#   Response: {"task": {...}, "progress": {...}, "findings_summary": [...]}

# GET /api/tasks/{task_id}/report?format=html
#   获取报告。format 可以是 html / json / markdown
#   Response: 对应格式的内容

# GET /api/tasks/{task_id}/finding/{finding_id}
#   获取单个 finding 的详情 + 事件历史
```

### 5.7 BatchRunner

```python
class BatchRunner:
    def __init__(self, pipeline: PipelineOrchestrator): ...

    def run(self, target_list: List[str],
            mode: str = "standard") -> List[AuditReport]:
        """
        对一批项目依次运行审计。

        Args:
            target_list: GitHub URL 或本地路径的列表
            mode: 审计模式

        Returns:
            每个项目的 AuditReport 列表
        """
        ...

    def generate_summary(self, reports: List[AuditReport]) -> str:
        """生成批量扫描汇总表（Markdown 格式）"""
        ...
```

---

## 六、路径常量

```python
# 所有人必须使用这些常量，禁止硬编码路径

WORKSPACE_ROOT = "./workspace"
REPOS_DIR = "./workspace/repos"           # B: clone 目标
LEDGERS_DIR = "./workspace/ledgers"        # A: Event Ledger 存储
EVIDENCE_DIR = "./workspace/evidence"      # C: 证据包存储
RESULTS_DIR = "./results"                  # C: 报告输出
INDEX_DB_PATH = "./workspace/index.db"      # A: TaskIndex SQLite
TEMP_DIR = "/tmp/veriaudit"               # B: 临时文件
```

---

## 七、错误处理约定

| 异常类 | 含义 | 谁抛 | 谁捕获 |
|--------|------|------|--------|
| `RepoCloneError` | git clone 失败 | B | C (Pipeline 标记 task 为 failed) |
| `InvalidRepoError` | 路径无效 | B | C |
| `SASTToolError` | SAST 工具执行失败 | B | B (记录 error 事件，跳过该工具) |
| `InvalidStateTransition` | 非法状态转换 | A | B / C |
| `TerminalStateModification` | 尝试修改终态 | A | B / C |
| `LedgerWriteError` | Event Ledger 写入失败 | A | 任何人（系统级错误） |
| `LLMAPIError` | LLM 调用失败 | B | B (重试 3 次后降级) |
| `ReportGenerationError` | 报告生成失败 | C | C |

---

## 八、契约测试

```python
# tests/contract/ — 三人第一周一起写

class TestSchema:
    def test_status_transitions(self): ...
    def test_terminal_immutable(self): ...
    def test_event_hash_computation(self): ...
    def test_finding_default_status_is_raw(self): ...

class TestALedger:
    def test_append_auto_fills_seq_and_hash(self): ...
    def test_hash_chain_integrity(self): ...
    def test_projection_returns_correct_status(self): ...

class TestBToCInterface:
    def test_repo_parser_returns_valid_profile(self): ...
    def test_static_scan_returns_raw_findings(self): ...
    def test_verification_agent_never_returns_confirmed_exploited(self): ...
    def test_llm_analyze_finding_returns_required_keys(self): ...

class TestCToExternal:
    def test_report_never_shows_confirmed_exploited(self): ...
    def test_dynamic_verifier_always_returns_not_implemented(self): ...
    def test_pipeline_completes_for_fixture_project(self): ...

class TestEndToEnd:
    def test_php_fixture_end_to_end(self):
        """
        用最小 fixture 项目跑全程。
        验证: RAW → CANDIDATE → VERIFIED_STATIC → DYNAMIC_NOT_IMPLEMENTED
        """
        ...
```

---

## 附录：每个方法的调用链

```
CLI / Web
    │
    └─→ PipelineOrchestrator.run()
            │
            ├─→ RepoParser.parse()                    [B]
            │       └─→ EventLedger.append()           [A]
            │
            ├─→ StaticScanAgent.scan()                [B]
            │       ├─→ Semgrep.run()                  [B]
            │       ├─→ Bandit.run()                   [B]
            │       ├─→ Gitleaks.run()                 [B]
            │       └─→ EventLedger.append()           [A]
            │
            ├─→ StaticVerificationAgent.verify()       [B]
            │       ├─→ LLMProvider.analyze_finding()  [B]
            │       ├─→ FindingStateMachine.transition()[A]
            │       └─→ EventLedger.append()           [A]
            │
            ├─→ FindingStateMachine.transition()       [A]
            ├─→ DynamicVerifier.verify()               [C]
            ├─→ FindingStateMachine.transition()       [A]
            │
            ├─→ JudgeEngine.judge()                    [A]
            │       └─→ FindingStateMachine.transition()[A]
            │
            └─→ ReportGenerator.generate()             [C]
                    ├─→ EventLedger.project_*()        [A]
                    ├─→ TaskIndex.save_report()        [A]
                    └─→ EvidencePackager.package()     [C]
```

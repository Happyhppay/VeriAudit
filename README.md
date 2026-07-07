# VeriAudit

基于 LLM 智能体编排的开源项目自动化安全审计与漏洞验证系统。

**VeriAudit** 是一个语言无关、项目无关的漏洞自动发现与验证系统。它整合了 SAST 工具（Semgrep、Bandit）、代码属性图谱（CPG）、Fuzz 引擎（libFuzzer + ASan）等多种确定性分析手段，由 LLM 智能体进行编排调度。

> ✅ **当前阶段：MVP 完成。** 46 个 Python 文件，12,308 行代码。核心引擎、8 个语言适配器、12 个漏洞类处理器、8 个 MCP Server、6 个 Agent、RAG 系统已全部实现。

## 核心原则

1. **证据优先**：SAST 告警、LLM 推理、CPG 路径都只是线索。最终漏洞认定必须基于动态验证结果。
2. **LLM 不下结论**：LLM 负责编排和推理，不做最终漏洞判定。最终裁定权在 Judge Engine（20 条确定性规则）。
3. **Event Ledger 是唯一真相来源**：所有状态变更是不可变事件的确定性投影。SHA-256 哈希链保证完整性。
4. **可复现是底线**：每个确认漏洞必须提供完整可复现包。

## 快速开始

```bash
pip install -r veriaudit/requirements.txt
pip install semgrep bandit

# 扫描本地项目
python -m veriaudit.cli.main audit ./my-project --mode standard

# 扫描 GitHub 仓库
python -m veriaudit.cli.main audit https://github.com/user/repo.git --mode quick
```

## 当前状态

| 指标 | 数值 |
|------|------|
| 代码量 | 46 文件 / 12,308 行 |
| 测试 | 107 passed |
| 语言适配器 | C/C++, PHP, Go, Java, Python, JS/TS, Rust, Ruby |
| SAST 工具 | semgrep + bandit |
| Docker 镜像 | veriaudit/cpp-fuzz (clang18 + libFuzzer + ASan + semgrep) |
| 已验证项目 | python/requests ✓, go/gin ✓, c/zlib ✓ |

## 项目结构

```
veriaudit/
├── core/           # 核心引擎 (EventLedger, 状态机, 裁决, 不变量, 容器池)
├── adapters/       # 三层抽象适配器 (language/ ×8, build/ ×3, vuln_class/ ×12)
├── mcp_servers/    # 8 个 MCP Server (repo, build, sast, cpg, fuzz, exploit, evidence, report)
├── agents/         # BaseAgent(ReAct) + Orchestrator(10 阶段) + 6 Agent
├── rag/            # Tree-sitter AST 分块 + ChromaDB 向量存储
├── cli/            # Click CLI 入口
├── docker/         # Dockerfile.cpp-fuzz (ASan + libFuzzer 镜像)
├── tests/          # 107 个测试用例
└── config/         # 默认配置
```

## 参考项目

VeriAudit 的设计借鉴了以下开源项目的精华：

| 项目 | 借鉴 |
|------|------|
| [DeepAudit](https://github.com/lintsinghua/DeepAudit) | ReAct Agent 循环、三层工具优先级、PoC 自修正、RAG 语义分块 |
| [AgentStalker](https://github.com/Gach0ng/AgentStalker) | 类型化 Source/Sink 污点图、确定性裁决规则、多容器沙箱观测 |
| [ESAA-Security](https://github.com/elzobrito/ESAA-Security) | 事件溯源架构、六个不变量、Event Ledger 作为真相来源 |
| [Sandyaa](https://github.com/securelayer7/sandyaa) | 递归自验证 Pass、Contradiction Detection、Attacker-Control 过滤 |
| [OpenSecurity](https://github.com/zylc369/OpenSecurity) | 三层分离架构（编排/工具/知识）、领域 Agent 设计 |

## 路线图

- [x] 架构设计完成
- [x] 接口契约完成
- [x] 三人分工方案完成
- [x] Core Engine (Event Ledger + 状态机 + 裁决引擎 + 不变量)
- [x] 适配层 (8 语言 + 3 构建 + 12 漏洞类处理器)
- [x] MCP Server (8 个，共 51 个工具)
- [x] Agent 层 (6 Agent + Orchestrator)
- [x] RAG 系统 + CLI + Docker
- [x] 端到端审计验证 (3 个真实项目)
- [ ] 后续: Web 动态验证 (OOB / 盲注 / 路径遍历)
- [ ] 后续: 20+ 开源项目批量审计

## License

MIT

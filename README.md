# 公众扫码来源核验与风险告知

面向日均数百万次扫码的药品/耗材追溯码来源核验后台的**领域内核**：按发布
规则返回可解释状态，敏感节点只展示必要摘要，查询缓存随权威更正与风险
升级精准失效。所有示例均为虚构数据，不含真实个人信息、账号或凭据。

## 模块

| 文件 | 职责 |
| --- | --- |
| `src/tracecodes.py` | 追溯码归一化、残损识别（绝不猜码）、校验位、指纹与脱敏 |
| `src/authority.py` | 只追加的权威轨迹库：事件、更正留痕、批次修订号、链路检查 |
| `src/statuses.py` | 五类发布状态的判定规则与弱信号（多地扫码）处理 |
| `src/privacy.py` | 公众视图裁剪：隔离受限字段、机构只到类型+省级区域 |
| `src/cache.py` | 版本感知缓存：精准失效、负缓存、旧结论依据历史档案 |
| `src/verifier.py` | 入口编排：重复扫码、离线补查、枚举熔断、降级 |
| `src/disputes.py` | 公众异议：受控证据隔离评审，不直接改写权威轨迹 |
| `src/subscriptions.py` | 显式订阅、二次确认、影响面过滤与按结论去重的通知 |

需求到实现的逐条映射见 [`docs/architecture.md`](docs/architecture.md)。
仓库中的 `contracts/context.schema.json` 描述基础领域资料，
`fixtures/context.json` 给出可公开使用的示例，`src/context.py` 负责读取
与校验。

## 本地校验

```bash
pip install -r requirements.txt
python -m pytest
```

测试覆盖追溯码处理、发布判定、隐私裁剪、缓存失效与历史依据、各类入口
分流、异议评审、订阅通知，以及一个串起完整业务叙事的端到端用例
（`tests/test_end_to_end.py`）。

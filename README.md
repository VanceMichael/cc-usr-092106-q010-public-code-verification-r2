# 公众扫码来源核验与风险告知

约定公众扫描药品追溯码时可见的来源状态和隐私范围。

## 领域资料

仓库中的 `contracts/context.schema.json` 描述基础资料格式，`fixtures/context.json` 给出可公开使用的示例。代码库只负责读取与校验这些资料，业务服务可沿用相同标识和版本约定。

当前资料反映的事实包括：

- 公众可通过平台扫码查询药品流转轨迹
- 查询量达到日均五百万人次以上
- 查询结果需要兼顾来源核验与隐私

## 本地校验

运行项目自带测试即可确认样例资料可读取，且领域标识与版本字段完整。所有示例均为虚构数据，不含真实个人信息、账号或访问凭据。

## 来源核验后台

`docs/source-verification.md` 是公众扫码来源核验后台的设计规约，覆盖五态发布规则
（生产可溯 / 合法流转 / 已召回 / 待复核 / 无法确认）、隐私最小摘要、缓存随权威更正
与风险升级精确失效、重复扫码/离线补查/恶意枚举/码不存在/残损输入的区分处理、
异议受控证据独立轨道、订阅风险通知与历史结论留痕。

对外契约与样例：

- `contracts/verification-result.schema.json` —— 公众核验结果契约（含状态、理由码、轨迹白名单、召回与待复核条件）
- `contracts/query-error.schema.json` —— 残损输入与限速错误契约
- `fixtures/verify/`、`fixtures/errors/` —— 覆盖全部五态（含陈旧缓存降级）的虚构样例
- `src/verification.py` —— 零第三方依赖的契约与发布规则校验器
- `tests/test_verification.py` —— 契约、发布规则与隐私白名单测试（`python -m unittest discover -s tests`）

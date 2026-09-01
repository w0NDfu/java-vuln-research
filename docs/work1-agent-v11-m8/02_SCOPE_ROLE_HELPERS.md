# Work1 V11 M8-2：Scope 与 Role Construction Helpers

## 1. 目标与边界

M8-2 修复 M7 proposal 构造中的两类工程错误，而不改变任何安全判断：

- 4 个 `EXTERNAL_INPUT` proposal 因 scope 未覆盖全部 anchors 被拒绝；
- 1 个 `FIELD_STATE` proposal 因缺少合法 field/source/target role 组合被拒绝。

新增 helper 只读取现有 `RepositoryIndex`、`ProgramEntity` 和 M4 proposal contract。它们不寻找 input/effect，不创建语义关系，不决定 evidence sufficiency，也不把 Gate admission 当作漏洞确认。`proposal/gate.py`、`proposal/validator.py` 和 `proposal/roles.py` 的准入标准均未修改。

## 2. Scope helper

实现：`m8_multiagent/scope_helper.py`

入口：

```python
build_valid_scope(
    repository_index,
    project_id=...,
    subject=...,
    source=...,
    target=...,
    proposal_type=...,
    preferred_scope=...,
)
```

输入 anchor 可以是 index 中的 `ProgramEntity`、`EntityRoleRef` 或 entity ID。任何未知 entity、同 ID 不同内容、空 project ID、wildcard/traversal project ID 都 fail closed。

算法按以下顺序选择最小结构边界：

1. `ENTITY_LOCAL`：只有一个不同 anchor；
2. `CALLABLE_LOCAL`：多个 anchors 共享同一 enclosing callable；
3. `TYPE_LOCAL`：不共享 callable，但共享 enclosing type；
4. `FILE_LOCAL`：不共享 type，但位于同一 repository-relative file；
5. `BOUNDED_EXPLICIT`：跨文件时仅列出明确 anchors。

`ScopePreview` 返回：

- canonical M4 `ProposalScope`；
- anchor IDs 与 covered anchor IDs；
- owner entity、file、callable、type；
- 为什么更小 scope 无效；
- preferred scope 是否不是最小边界的 warning。

M4 当前没有独立 `TYPE`/`FILE` scope kind。helper 不扩展或绕过 schema：type/file locality 记录在 preview 中，最终用显式 bounded `ENTITY` scope；`FIELD_STATE`、`FRAMEWORK_RELATION`、`CALLBACK_RELATION` 继续使用现有 M4 kind，callable-local flow 使用 `CALLABLE`。

Scope 中只列 proposal anchors，不自动扩大到 project，也不添加无关 owner entity。最终产物仍由原 `validate_scope()` 和 `EvidenceGate` 检查。

## 3. Role helper

实现：`m8_multiagent/role_helper.py`

入口：

```python
build_role_guidance(
    repository_index,
    entity=...,
    proposal_type=...,
    observed_source_structure=...,
)
```

helper 枚举当前 entity 的全部 `EntityRoleRef` 候选，并逐个调用原 M4 `validate_role()`。因此 argument/parameter index、entity kind compatibility 和 role-index requirements 与 Gate 使用同一标准，不存在第二套角色判定系统。

`RolePreview` 按 `subject/source/target` 返回：

- M4 合法 role 与 role index；
- proposal-specific required/optional/forbidden anchors；
- proposal shape 允许的 role 子集；
- 一个结构合法的 schema example；
- 已观察 source structure 的可审计副本。

关键 shape contract：

| Proposal type | Required anchors | 特殊 role 约束 |
|---|---|---|
| `EXTERNAL_INPUT` | subject | source/target 禁止 |
| `SECURITY_EFFECT` | subject | source/target 禁止 |
| `WRAPPER_FLOW` / `LIBRARY_FLOW` | subject/source/target | 每个 ref 仍须通过 M4 role validation |
| `FIELD_STATE` | subject/source/target | subject=`FIELD`; source=`FIELD_WRITE/ARGUMENT/PARAMETER`; target=`FIELD_READ/RETURN` |
| `FRAMEWORK_RELATION` | subject/target | source 可选 |
| `CALLBACK_RELATION` | subject/target | target=`METHOD/PARAMETER/ARGUMENT`; source 可选 |

Schema example 的排序按 proposal purpose 偏向 value role，例如 External Input 的 callable 优先展示 `PARAMETER`/`RETURN`，Security Effect 的 call 优先展示 `ARGUMENT`/`RECEIVER`。这只是结构引导；API 名、method 名和 category 不参与选择。

## 4. M7 失败形态回归

### 4.1 External Input scope

旧失败形态中的 subject anchor 经 `build_valid_scope()` 后必定出现在 `scope.entity_ids`。单一 method return 使用 `ENTITY_LOCAL`，不会扩大到 project；原 `validate_scope()` 返回空错误列表。

### 4.2 FIELD_STATE role

对 indexed field，helper 返回：

- subject：`FIELD`；
- source：`FIELD_WRITE`；
- target：`FIELD_READ`。

测试使用 helper 的 schema example 与 scope 构造真实 `SecurityProposal`，再交给未修改的 M4 `EvidenceGate`。`ROLE_COMPATIBILITY=PASS`，在 direct repository evidence 下结果为 `ADMISSIBLE`。这只证明 contract 构造正确，不证明 field relation 或漏洞成立。

## 5. 已知限制

Role helper 不覆盖或修补 M1 lexical index。controlled fixture 中嵌套调用 `Files.writeString(Path.of(path), ...)` 的 `argument_count` 当前为 1；helper 只暴露 index 记录支持的 argument roles，不凭源码直觉发明第二个参数。后续若增强 callsite parser，必须作为通用 repository capability 单独测试，并保持现有 Gate 不变。

`observed_source_structure` 只进入结构化 preview/provenance，不覆盖 `ProgramEntity.provenance`。需要新的 role index 时，必须先由 repository/CodeQL tool 产生可审计结构事实。

## 6. 测试

新增：

- `tests/unit/test_m8_scope_helper.py`
- `tests/unit/test_m8_role_helper.py`

覆盖：

- External Input scope repair；
- entity/callable/type/file/explicit 最小边界；
- unknown entity、wildcard 和 traversal fail closed；
- M4 relation-specific scope kind；
- callable parameter/return role；
- bounded call argument index；
- FIELD_STATE 完整 role contract 与原 Gate admission；
- CALLBACK target role restriction；
- helper 不输出 vulnerability/security category 结论。

本地验证：

- scope/role helper targeted：`10 passed`；
- all M8 deterministic tests：`24 passed, 2 warnings`；
- full regression：`285 passed, 2 skipped, 5 warnings`；
- `python -m compileall -q src tests`：通过；
- `git diff --check`：通过。

warnings 仍为既有 `jsonschema.RefResolver` deprecation。CloudStudio exact-commit 回归结果在里程碑提交并推送后追加，不改写本次正式逻辑身份。

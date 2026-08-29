# Work1 V11 M1：ProgramEntity 与 RepositoryIndex

日期：2026-08-29

状态：`M1_COMPLETE / CLOUDSTUDIO_SMOKE_COMPLETE`

## 1. M1 目标

M1 建立一个不依赖 CodeQL Source、Sink、partial-flow 或完整路径的中性程序实体层。输入仅为 Java repository root；输出为可审计的 ProgramEntity JSONL、汇总 JSON 和诊断 JSONL。

本阶段不判断漏洞，不分类 Source/Sink，不包含 CWE、危险方法名或 Route B 式候选规则，也不实现 Agent Tools。

## 2. ProgramEntity Schema

Schema 位于 `schemas/program_entity.schema.json`。当前支持：

```text
FILE
PACKAGE
TYPE
METHOD
CONSTRUCTOR
PARAMETER
FIELD
CALL
ANNOTATION
```

为后续阶段预留但 M1 不提取：

```text
RETURN
LOCAL
CALL_ARGUMENT
FIELD_READ
FIELD_WRITE
```

每个实体包含：

- `entity_id`
- `codeql_identity`（M1 为 `null`，M3 可在不改变实体 ID 的情况下补充）
- `kind`
- `repository_relative_path`
- `start_line` / `end_line`
- `simple_name` / `qualified_name`
- `enclosing_type` / `enclosing_callable`
- `signature` / `type_text`
- `provenance`
- `extraction_confidence`

置信状态为 `HIGH`、`MEDIUM`、`LOW`、`UNKNOWN`。词法可确定的文件、包、类型和正常声明通常为 `HIGH`；缺少类型解析的数据如调用和字段为 `MEDIUM`；受不匹配括号影响的结构为 `LOW`。

## 3. Entity ID 设计

`entity_id` 为以下规范化材料的 SHA-256 前 24 个十六进制字符，并带 `entity-` 前缀：

```text
schema version
entity kind
POSIX repository-relative path
start/end line
simple/qualified name
enclosing type/callable
signature
type text
source-local identity discriminator
```

绝对路径、repository root 和 `codeql_identity` 不进入 identity。Windows `\` 与 POSIX `/` 先统一为 `/`；绝对路径和 `..` 被拒绝。

方法签名包含规范化参数类型，因此重载方法拥有不同 ID；构造器使用独立的 `CONSTRUCTOR` kind。相同 repository、commit 和提取器版本重复构建时，JSONL 与 entity ID 稳定。

## 4. RepositoryIndex 实现

入口：

```bash
PYTHONPATH=src python3 -m java_vuln_research.work1_agent.repository.indexer \
  --repository-root /path/to/project \
  --output /path/to/output/program_entities.jsonl \
  --summary /path/to/output/summary.json \
  --diagnostics /path/to/output/diagnostics.jsonl
```

CloudStudio 也可使用：

```bash
bash scripts/run_work1_v11_m1_index.sh /path/to/project /path/to/output
```

索引器按规范化相对路径排序 Java 文件，使用 UTF-8 strict decoding，生成 FILE 后提取包、类型、方法、构造器、参数、字段、调用和注解。实体按路径、范围、kind、名称、签名和 ID 稳定排序后写入 JSONL。

默认排除 `.git`、`.gradle`、`.idea`、`build`、`node_modules`、`out`、`target`，避免把构建产物和生成副本当作 repository source。CLI 可用重复的 `--exclude-dir` 显式替换默认集合。

Summary 包含：Java 文件数、实体总数、逐 kind 数量、逐 confidence 数量、LOW/UNKNOWN 数量、warning/error 数量、耗时和排除目录。

## 5. Bounded Source Reader

`reader.py` 实现：

- `read_file_range(...)`
- `inspect_entity(...)`

保护条件：

- repository root 必须存在；
- 仅接受 repository-relative path；
- resolve 后再次检查 root confinement，防止 `..` 和逃逸 symlink；
- 默认最多 250 行、64 KiB 返回内容；
- hard ceiling 为 1,000 行、1 MiB；
- UTF-8 解码失败返回明确的 `UTF8_DECODE_ERROR`；
- 输出包含逐行 `{line, text}` 和带行号的 `text`；
- 超过行数、字节数或范围时失败，不静默返回超大类或方法。

## 6. Neutral Repository Search

`search.py` 实现：

- `search_code(index, query, file_glob=None, max_hits=30)`
- `search_symbols(index, query, kind=None, max_hits=30)`

最大命中数 hard ceiling 为 100。返回字段固定为：

```text
entity
location
snippet
kind
query
provenance
```

搜索结果只描述代码文本和符号事实，不产生安全角色、漏洞状态或 CWE 判断。`search_code` 将文本命中关联到覆盖该行的最小实体；`search_symbols` 搜索实体名称、限定名和签名。

## 7. 保守词法扫描边界

实现是标准库词法/brace-aware scanner，不是 Java compiler 或 AST：

1. 状态机先遮蔽行注释、块注释、字符串、字符和 text block，同时保留换行位置。
2. token scanner 建立括号、圆括号和 brace depth。
3. 类型和 callable 只在可证明的直接 owner depth 提取。
4. 多行签名、泛型、参数注解、嵌套类型、interface、constructor 和 overload 使用规范化 token 处理。
5. 无法闭合的 brace/parenthesis 写入 diagnostics；受影响实体保留但标为 LOW。
6. CALL 和 FIELD 不做类型解析，因此为 MEDIUM；它们不能被解释为任何安全语义。

已知边界：

- 不解析 import 或解析类型到 classpath 中的真实符号；
- 不支持完整 Java Unicode identifier 规则；
- lambda、anonymous/local class、复杂 enum body、annotation default 和多个字段共用一个声明的情况可能只得到部分实体；
- 调用只记录词法名称、arity 和 owner，不解析动态 dispatch；
- 行号变化会改变同一 commit 之外的 entity ID；跨 commit identity 对齐不属于 M1；
- M3 应用 CodeQL facts enrichment 时填充 `codeql_identity` 或 provenance，不应把不确定词法事实提升为高置信语义。

## 8. Controlled Tests

Fixture：`tests/fixtures/work1_agent_repository/`。

覆盖：package、annotation、interface、implementation、constructor、overloaded methods、nested class、fields、parameters、calls、multiline generic signature、comment braces、string braces 和 malformed Java。

受控 fixture 实际结果：

| 指标 | 结果 |
| --- | ---: |
| Java files | 2 |
| ProgramEntity | 42 |
| FILE | 2 |
| PACKAGE | 2 |
| TYPE | 6 |
| METHOD | 6 |
| CONSTRUCTOR | 3 |
| PARAMETER | 8 |
| FIELD | 4 |
| CALL | 8 |
| ANNOTATION | 3 |
| HIGH | 27 |
| MEDIUM | 12 |
| LOW | 3 |
| warnings | 2 |
| errors | 0 |

两个 warning 都来自刻意残缺的 `Broken.java` 未闭合 brace。定向 M1 测试结果：`23 passed`（在最终提交前复跑冻结）。全仓库结果：`82 passed, 1 skipped`（在最终提交前复跑冻结）；skip 为本地缺少 CodeQL 的既有集成测试。

测试断言包括确定性 ID、路径规范化、重复抑制、source range、reader line/byte limit、path traversal、防 UTF-8 静默替换、稳定 JSON、嵌套 owner、重载 identity、默认构建目录排除以及中性搜索的 bounded 输出。

## 9. 两个真实项目 CloudStudio Smoke

当前状态：`COMPLETE`。

2026-08-29 在 CloudStudio terminal 执行。为保留 `/workspace/java-vuln-research` 的既有脏工作区和当前分支，未在原 checkout 上切分支；从 `origin/work1/agent-active-security-v11` 建立独立 detached worktree：

```bash
git -C /workspace/java-vuln-research fetch origin work1/agent-active-security-v11
git -C /workspace/java-vuln-research worktree add --detach \
  /workspace/work1-v11-m1-d0ae252-20260829 \
  origin/work1/agent-active-security-v11
```

执行 HEAD：`d0ae25272f0370da39259cbf0e4536cbb26e847b`。测试对象是云端已有的两个独立真实项目 checkout：

- Retrofit：`https://github.com/square/retrofit`，HEAD `7158698314daa138e993fac6a590ed19d78a8599`；
- Hutool：`https://github.com/dromara/hutool`，HEAD `7687720c5125b29386d3bb9c7c2931da79664b73`。

执行命令：

```bash
/usr/bin/time -p bash \
  /workspace/work1-v11-m1-d0ae252-20260829/scripts/run_work1_v11_m1_index.sh \
  /workspace/w1-e1-dev16/projects/V001 \
  /workspace/experiment-output/artifacts/work1-agent-v11/m1_repository_index/retrofit

/usr/bin/time -p bash \
  /workspace/work1-v11-m1-d0ae252-20260829/scripts/run_work1_v11_m1_index.sh \
  /workspace/w1-e1-dev16/projects/V002 \
  /workspace/experiment-output/artifacts/work1-agent-v11/m1_repository_index/hutool
```

| Project | Repo root | Java files | Entities | TYPE | METHOD | CONSTRUCTOR | PARAMETER | FIELD | CALL | ANNOTATION | LOW | Warnings | Errors | Wall-clock |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Retrofit | `/workspace/w1-e1-dev16/projects/V001` | 220 | 17,702 | 556 | 1,696 | 154 | 1,140 | 533 | 10,894 | 2,289 | 0 | 0 | 0 | 2.50 s |
| Hutool | `/workspace/w1-e1-dev16/projects/V002` | 889 | 47,003 | 858 | 7,487 | 895 | 10,354 | 1,780 | 21,586 | 2,265 | 0 | 0 | 0 | 7.07 s |

补充 confidence：Retrofit 为 HIGH 6,275 / MEDIUM 11,427；Hutool 为 HIGH 23,637 / MEDIUM 23,366。两个项目均无 LOW/UNKNOWN、warning 或 error，命令退出码均为 0。

按固定随机种子抽查每个项目的 TYPE、METHOD、CONSTRUCTOR、CALL 各 1 个，并从项目 checkout 重新读取 `start_line` 对应源码，验证 `1 <= start_line <= end_line <= file_line_count`。8/8 样本的路径、范围、owner 和 signature 均匹配，`valid_range=true`。代表性记录：

| Project / kind | Location | Owner | Signature |
| --- | --- | --- | --- |
| Retrofit / TYPE | `retrofit/src/test/java/retrofit2/RequestBuilderTest.java:726` | `retrofit2.RequestBuilderTest` | `class Example` |
| Retrofit / METHOD | `samples/src/main/java/com/example/retrofit/ErrorHandlingAdapter.java:89` | `com.example.retrofit.ErrorHandlingAdapter.ErrorHandlingCallAdapterFactory.ErrorHandlingCallAdapter` | `adapt(Call<R>)` |
| Retrofit / CONSTRUCTOR | `retrofit-mock/src/main/java/retrofit2/mock/Calls.java:59-65` | `retrofit2.mock.Calls.FakeCall` | `FakeCall(Response<T>,IOException)` |
| Retrofit / CALL | `retrofit/src/main/java/retrofit2/ParameterHandler.java:337` | `retrofit2.ParameterHandler.PartMap.apply(RequestBuilder,Map<String,T>)` | `addPart/2` |
| Hutool / TYPE | `hutool-core/src/main/java/cn/hutool/core/text/ASCIIStrCache.java:10` | top-level | `class ASCIIStrCache` |
| Hutool / METHOD | `hutool-core/src/test/java/cn/hutool/core/io/FileUtilTest.java:57` | `cn.hutool.core.io.FileUtilTest` | `copyTest()` |
| Hutool / CONSTRUCTOR | `hutool-core/src/main/java/cn/hutool/core/thread/NamedThreadFactory.java:39` | `cn.hutool.core.thread.NamedThreadFactory` | `NamedThreadFactory(String,boolean)` |
| Hutool / CALL | `hutool-core/src/main/java/cn/hutool/core/util/IdcardUtil.java:462` | `cn.hutool.core.util.IdcardUtil.getDayByIdCard(String)` | `substring/2` |

抽样种子为 Retrofit `1101`、Hutool `1202`；完整 JSONL 位于同一 cloud artifact root 下的 `retrofit_kind_samples.jsonl` 与 `hutool_kind_samples.jsonl`。该 smoke 未读取或构建 CodeQL DB，也未运行 CodeQL 命令或进行漏洞评价。

## 10. 文件变更

```text
schemas/program_entity.schema.json
scripts/run_work1_v11_m1_index.sh
src/java_vuln_research/work1_agent/__init__.py
src/java_vuln_research/work1_agent/repository/__init__.py
src/java_vuln_research/work1_agent/repository/entity.py
src/java_vuln_research/work1_agent/repository/indexer.py
src/java_vuln_research/work1_agent/repository/reader.py
src/java_vuln_research/work1_agent/repository/search.py
tests/fixtures/work1_agent_repository/src/main/java/com/example/Broken.java
tests/fixtures/work1_agent_repository/src/main/java/com/example/RepositoryCases.java
tests/unit/test_program_entity.py
tests/unit/test_repository_index.py
docs/work1-agent-v11/01_REPOSITORY_INDEX.md
```

未修改 Route B、现有 Candidate IR、现有 CLI 或 CodeQL query。M0 前的脏工作区文件继续保持原状。

## 11. 当前问题

1. 词法 scanner 的结构真实性低于 Java AST/CodeQL；diagnostic 和 confidence 必须由后续消费者保留。
2. 当前 source reader 为 bounded response，但会先读取单个文件字节；超过 64 MiB 的文件被拒绝。
3. 当前没有跨 commit entity matching。
4. 当前 search 为 repository facts，不提供 caller/callee、override 或 implementation resolution。

## 12. M2 所需接口

M2 可以复用：

- `RepositoryIndex.entities` / `sorted_entities()`；
- `ProgramEntity.to_dict()` / `from_dict()`；
- `read_file_range()` / `inspect_entity()`；
- `search_code()` / `search_symbols()`；
- index summary 与 diagnostics。

M2 才增加 `inspect_method`、`inspect_type`、caller/callee、implementation、override、field、annotation 的 Agent Tool façade、tool JSON schema、bounded tool output、JSONL trace 和 tool-call provenance。M1 不实现这些工具，也不进入 Agent 或安全语义判断。

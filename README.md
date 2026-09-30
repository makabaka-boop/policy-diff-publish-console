# PolicyLab · 有限域模拟访问策略

一个 **教学/演示用** 的模拟沙盒：在一个有限决策域
（角色 × 资源类别 × 操作）上编辑访问策略，穷举预览草稿相对已发布版本的差异，
并通过「三重版本凭证」安全发布。

> ⚠️ 本项目不是任何真实系统的鉴权入口：没有真实用户、会话或受保护资源，
> 所有状态保存在内存中，重启即重置。响应头带有
> `X-PolicyLab: simulation-only; not a real authz endpoint`。

## 模型

- **角色**：至多 8 个；角色之间通过 `parents` 形成**无环继承图（DAG）**，
  子角色继承父角色的规则（支持菱形继承）。
- **资源类别**：至多 8 个；**操作**：至多 6 种。
- **规则**：按 `role / resource / action` 匹配，三者均支持精确值或 `*` 通配；
  带整数 `priority`（越大越优先）与 `allow / deny` 效果。
- **裁决规则**：
  1. 收集所有命中规则（角色命中考虑继承闭包）；
  2. 按优先级降序排序；
  3. **同优先级 deny 胜过 allow**（规则 ID 作为最终稳定次序）；
  4. **未命中任何规则 → 默认 deny**。

## 版本与发布协议

- 服务器维护 `draftRevision`（草稿修订）与 `publishedRevision`（已发布修订）。
- `PUT /api/draft` 必须携带 `baseDraftRevision`（乐观并发），保存成功才推进修订。
- `POST /api/preview` 穷举整个有限域，对比草稿与已发布版本，返回：
  - `newAllows`：基线 deny → 草稿 allow，逐条带**草稿与基线双方的命中规则证据**；
  - `newDenies`：基线 allow → 草稿 deny，同样带双方证据；
  - `draftRevision / publishedRevision / digest`：绑定本次预览的三重凭证
    （`digest` 为含修订号与全部差异内容的 SHA-256）。
- `POST /api/publish` 必须同时带回 `draftRevision`、`publishedRevision`、`previewDigest`。
  服务器在锁内重新穷举当前状态并比对摘要：
  - 草稿在预览后被保存过 → 草稿修订不匹配 → **409 拒绝**；
  - 另一客户端已抢先发布 → 已发布修订不匹配 → **409 拒绝**；
  - 摘要为空/伪造/与当前状态不符 → **409 拒绝**。

  因此**不可能发布未经预览的混合版本**。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/state` | 当前草稿、已发布版本、两个修订号、域上限 |
| PUT | `/api/draft` | 整体保存草稿（需 `baseDraftRevision`；服务端做完整校验） |
| POST | `/api/preview` | 穷举预览；body 可空（预览当前草稿）或带 `{policy, baseDraftRevision}` 预览候选草稿 |
| POST | `/api/publish` | 三重凭证发布 |

错误响应：`400 invalid_body / invalid_policy`、`409 revision_stale / preview_mismatch`。

## 前端

单页 `web/index.html`（Vue 3，本地内置 `vendor/vue.global.prod.js`，无外网依赖）：

- 左侧编辑角色（含父角色多选）、资源、操作、规则；
- 右侧生成预览，分栏列出新增允许/新增拒绝及命中规则证据（含继承来源标注）；
- 顶部有 **客户端 A / 客户端 B** 两个互不共享状态的标签页，专门用来演练并发：
  预览过期会立即在页面上标红，发布按钮在修订不一致时禁用，竞争发布会收到 409 提示。

## 运行

```bash
go run .                       # 默认监听 :8080
go run . -addr :9090
# 然后浏览器打开 http://localhost:8080
```

构建：

```bash
CGO_ENABLED=0 go build -o policylab .
```

## 测试

```bash
CGO_ENABLED=0 go test ./...
```

覆盖场景：

- **角色继承菱形**：`superanalyst` 同时继承 `analyst`/`auditor`（二者共同继承 `reader`），
  经两条路径获得权限，证据中标注继承来源（`internal/policy/policy_test.go`）；
- **同优先级冲突**：同优先级 allow/deny 共同命中时 deny 胜出，证据保留全部命中规则；
  高优先级 allow 仍可压过低优先级 deny；
- **规则编辑后的过期预览**：先预览、再保存草稿，旧三重凭证发布必须 409；
- **两个客户端竞争发布**：相同状态各自预览，先发布者成功、后发布者 409，
  刷新并重新预览后才能再次发布；
- 另含：默认 deny、通配符、域上限、环/自环/悬空父角色/坏引用校验、
  伪造摘要拒绝、候选预览的修订守卫等。

## 目录结构

```
main.go                     入口 + 内嵌 web/ 静态资源
internal/policy/            有限域模型、裁决、穷举对比、摘要、校验
  policy.go  validate.go  seed.go  policy_test.go
internal/server/            HTTP API、修订号与乐观并发
  server.go  server_test.go
web/                        Vue 3 单页
  index.html  app.js  style.css  vendor/vue.global.prod.js
```

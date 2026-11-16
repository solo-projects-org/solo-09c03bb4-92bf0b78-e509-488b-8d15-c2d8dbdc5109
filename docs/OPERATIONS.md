# 运维与故障处理手册

## 1. 部署清单

| 组件 | 镜像 | 持久卷 | 暴露 |
|---|---|---|---|
| image-api | microscopy/image-api:1.0.0 | api-data（metadata.db + blobs/） | 8000 |
| keystore | microscopy/keystore:1.0.0 | keystore-data（keystore.db） | 127.0.0.1:8001 |

两个容器必须配置相同的 `KEY_SERVICE_TOKEN`。密钥服务端口只绑回环地址，
不应对仪器网段或公网暴露。

## 2. 数据与密钥位置

- 主密钥材料：仅 `keystore-data` 卷内 SQLite 的 `master_keys.key_material`；
  销毁后该列被 32 字节零覆写、状态置 `destroyed`，不可恢复。
- 数据密钥：永远以 64 字节信封（`MAGIC|nonce|ct|tag`）存在 api-data 的
  `images.wrapped_dek`；明文 DEK 只在 API 单次请求内存中出现。
- 原片：api-data 的 `blobs/*.msef`，全部为 AES-256-GCM 分帧密文；
  明文不落盘（multipart 假脱机已在代码中禁用）。

备份策略：两卷需**一起**备份。单独备份 api-data 在旧 MK 销毁后无法解读；
单独备份 keystore-data 没有原片。建议离线备份 keystore-data 并严格限制访问。

## 3. 标准轮换流程

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"confirm":true}' \
  http://localhost:8000/rotations
# 轮询 GET /rotations/{job_id}，state 终态：completed / failed
```

状态机：`migrating`（逐信封 rewrap，blob 正文不动）→ `destroying`
（零残留核验 + 抽样核实可读 + 销毁旧 MK + 只读核实）→ `completed`。

密钥服务暂时不可达（连接失败/5xx）时作业进入 **`retrying`**（非终态），
按指数退避持续重试；`error`/`attempts`/`next_retry_at` 可查。等待期间上传/
下载照常，作业持续阻塞新轮换。服务恢复即自动继续，**无需重启 API**。

只有确定性错误才落 `failed`：`permanent=1` 表示不可自动恢复（如旧 MK 已被
外部销毁、信封无法解包）；`permanent=0` 的 `failed`（旧版本遗留/瞬时故障）
会在启动或空闲时自动重新入队接续。仍有 `ready/receiving` 行依赖旧 MK 时，
`POST /rotations` 返回 `409 rotation_pending_dependencies`，必须先完成续作。

## 4. 故障演练开关（keystore）

- `KEY_OP_DELAY=<秒>`：模拟慢密钥服务，验证在线流量不被轮换拖死。
- `KEY_DESTROY_DROP_RECEIPT=true`：销毁落盘后丢弃 HTTP 回执，验证 API
  自动重试 + 只读状态核实、作业仍如实报 completed。
- `KEY_FAIL_OPS=rewrap,unwrap`（逗号分隔，可选 rotate/generate/destroy）：
  指定操作返回 503，验证作业进入 `retrying` 而非误判失败；清空该变量并重启
  密钥服务即可验证自动接续。注意生产排障时不要保留此变量。
- `ROTATION_VERIFY_SAMPLE`（API 侧，默认 50）：销毁前抽样的 ready 原片数，
  设为 0 关闭抽样（不建议）。

## 5. 崩溃/重启语义

| 场景 | 行为 |
|---|---|
| API 在上传中崩溃 | 重启后该件标 `failed`（不晚发布）；blob 残片可按 failed 行清理 |
| API 在轮换中崩溃 | 重启后后台线程自动接续 `migrating/retrying/destroying` 到终态 |
| 轮换作业已 failed（旧版本遗留） | 启动/空闲时自动重新入队接续；`permanent=1` 除外 |
| 崩溃于"MK 已切换、作业未建"窗口 | 启动对账自动补建迁移作业；启动时密钥服务不可达则在空闲期对账补建 |
| 密钥服务短暂不可用 | 作业停留 `retrying` 并退避重试；恢复后自动继续，不误报失败 |
| 密钥服务重启 | 主密钥从卷内 SQLite 恢复，已入湖原片逐字节可读 |
| 销毁回执丢失 | KeyClient 重试并以 `/internal/master/status` 只读核实 |
| 旧版元数据库 | 启动自动升级 `rotation_jobs`（新增 `retrying`/`attempts`/`permanent` 等），历史作业保留 |

## 6. 已知限制（单实例/SQLite 范围之外）

1. 单实例：API 与密钥服务均为单节点，无水平扩展与高可用；多实例需要
   分布式轮换锁（如 Postgres 行锁/etcd）与共享对象存储。
2. 内部服务间为共享 Bearer 令牌；生产化建议改 mTLS 并加调用审计。
3. 根密钥目前为软件随机生成并存于 SQLite；更高合规要求应替换为 HSM/KMS，
   本服务的信封接口（generate/unwrap/rewrap）保持不变即可适配。
4. GCM 帧验签失败发生在流式响应开始之后，表现为连接中断（HTTP 流无法
   再改状态码）；客户端应将不完整响应当作失败，可重新 GET 重试。
5. 销毁 MK 是不可逆操作；销毁前系统保证无 ready/receiving 行依赖它，
   并抽样核实迁移后的信封可解包，然后才销毁；销毁后再以只读 status 核实。
   若旧 MK 在作业以外被提前销毁，仍依赖它的行会被如实标 `failed`
   （下载返回 409），对应作业置 `permanent=1`，不会再自动重试。
6. 轮换线程是单实例内的常驻协程；多实例部署前必须先做分布式轮换锁，
   否则两个实例可能同时驱动同一作业（条件 UPDATE 能防信封覆盖，但无法
   防止重复销毁/重复对账）。

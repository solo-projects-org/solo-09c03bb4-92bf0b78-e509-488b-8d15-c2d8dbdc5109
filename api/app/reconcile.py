"""轮换作业对账（启动时与空闲运行期共用）。

关键语义：密钥服务里的“当前 MK 之外、仍 active”的旧主密钥，或图像行里仍
有 ready/receiving 依赖的旧 MK，都必须有对应的本地轮换作业；否则旧信封
永远不会被迁移、旧密钥也永远不会被销毁。

覆盖窗口：
  * API 已切换 MK 但还没来得及建本地作业就崩溃；
  * API 启动时密钥服务不可达（启动对账被跳过），稍后服务恢复；
  * 旧版本遗留的 failed 作业已被清理/丢失，仅剩旧依赖行。
"""
from __future__ import annotations

from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB


async def reconcile_rotations(db: MetadataDB, keys: KeyClient) -> None:
    status = await keys.master_status()
    current = status.get("current_key_id")
    if not current:
        return
    candidates: list[str] = []
    for key in status.get("keys", []):
        if key["key_id"] != current and key["state"] == "active":
            candidates.append(key["key_id"])
    # 图像行里仍有 ready/receiving 依赖的旧 MK（含被外部销毁的）也要建作业：
    # 前者需要迁移，后者会把不可读行如实判失败并解除阻塞。
    for old in db.rows_under_other_key(current):
        if old not in candidates:
            candidates.append(old)
    for old_key in candidates:
        if db.has_rotation_for(old_key):
            continue
        if db.active_rotation() is not None or db.next_failed_rotation() is not None:
            return  # 先让现有作业跑完，下一轮对账再补建
        total = db.count_under_key(old_key, only_migratable=True)
        try:
            job_id = db.create_rotation(old_key, current, total)
        except RuntimeError:
            return  # 已有作业被并发建立：下一轮对账再补齐其余旧 MK
        print(f"[rotation] reconciled missing rotation job {job_id} "
              f"for {old_key} ({total} row(s) depending on it)")


__all__ = ["reconcile_rotations", "KeyServiceError"]

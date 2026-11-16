"""主密钥轮换后台工作线程。

状态机（状态持久化在 rotation_jobs，进程重启可接续）：
  migrating  ->  逐行 rewrap 信封（不重写图像密文正文）
  retrying   ->  密钥服务暂不可用；带退避等待，恢复后自动回到 migrating
                 （非终态：不会被误判失败，也继续阻塞新轮换）
  destroying ->  零残留核验 + 抽样解包核实可读 + 销毁旧 MK + 只读状态核实
  completed  ->  仅当销毁已由密钥服务只读接口核实
  failed     ->  仅永久性错误（旧密钥被外部销毁、信封无法解包等）；
                 permanent=0 的旧失败作业会在启动/空闲时自动重新入队

并发生态保证：
  * 全程不持锁阻塞下载/上传；慢下载解包走旧 MK（销毁前完成解包即不受影响），
    下载中的帧解密只在本进程内存用明文 DEK，与密钥服务无关；
  * rewrap 用条件 UPDATE（WHERE master_key_id=旧），迟到的在途上传若已自行
    改绑新 MK 则自动跳过；
  * 销毁前扫残留（ready 与 receiving 都必须零依赖）并抽样解包核实新信封可读；
  * 同一时刻只允许一个轮换作业（DB 约束 + 新轮换入口的阻塞检查）；
  * 常驻线程每秒轮询未完成作业，进程重启后自动接续，不依赖唤醒信号。
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import traceback

from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB
from .reconcile import reconcile_rotations

POLL_INTERVAL = 1.0
RECONCILE_INTERVAL = 10.0    # 空闲时与密钥服务对账的间隔（秒）
BATCH_PAUSE = 0.02           # 批次间让出，避免挤占在线流量
RETRY_BASE = 0.5             # 密钥服务暂不可用时的退避起点（秒）
RETRY_MAX = 30.0             # 退避上限；一直重试到服务恢复，不放弃作业
# 销毁前抽样解包多少件 ready 原片来核实新信封确实可读（0 = 跳过抽样）
VERIFY_SAMPLE = int(os.environ.get("ROTATION_VERIFY_SAMPLE", "50"))
# 超过此时长仍处于 receiving 的上传视为僵死（崩溃残留由启动恢复处理，
# 这里兜底处理连接挂起），判失败以解除对轮换销毁阶段的阻塞。
UPLOAD_STALE_SECONDS = float(os.environ.get("UPLOAD_STALE_SECONDS", "3600"))

# 这些 HTTP 状态码代表确定性业务错误，重试不会自愈 -> 作业标记永久失败
PERMANENT_KEY_ERRORS = (400, 404, 410)


class RotationWorker:
    def __init__(self, db: MetadataDB, keys: KeyClient,
                 loop: asyncio.AbstractEventLoop):
        self._db = db
        self._keys = keys
        self._loop = loop
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_reconcile = 0.0

    def start(self):
        self._thread = threading.Thread(target=self._thread_main, daemon=True,
                                        name="rotation-worker")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _thread_main(self):
        try:
            fut = asyncio.run_coroutine_threadsafe(self._run(), self._loop)
            fut.result()
        except Exception:
            traceback.print_exc()

    async def _run(self):
        """常驻协程：发现未完成作业就驱动到终态，然后继续轮询。

        单轮循环内的意外异常不得终止常驻线程（否则后续轮换永久停滞），
        记录后退避继续；作业级异常已在 _drive_job 内落 failed/retrying。
        """
        while not self._stop.is_set():
            try:
                job = self._db.active_rotation()
                if job is not None:
                    await self._drive_job(job["job_id"])
                    continue
                # 空闲：定期与密钥服务对账（补齐启动时服务不可达而跳过的作业），
                # 并接续“旧版本遗留/瞬时失败”的终态作业。
                if time.time() - self._last_reconcile >= RECONCILE_INTERVAL:
                    self._last_reconcile = time.time()
                    try:
                        await reconcile_rotations(self._db, self._keys)
                    except KeyServiceError:
                        pass  # 服务仍不可用：保持现状，下次再试
                    if self._db.active_rotation() is not None:
                        continue
                self._resume_failed_jobs()
                await asyncio.sleep(POLL_INTERVAL)
            except asyncio.CancelledError:
                raise
            except Exception:  # 防御：记录并继续，不让守护线程静默退出
                traceback.print_exc()
                await asyncio.sleep(POLL_INTERVAL)

    def _resume_failed_jobs(self):
        """空闲时接续一个 failed 作业（旧版本遗留或运行期判定的瞬时失败）。

        多把旧 MK 同时残留时逐个续作：先接最早的，完成后自然轮到下一把。
        旧 MK 已无 ready/receiving 依赖的失败作业也会重新入队，直接走销毁。
        """
        job = self._db.next_failed_rotation()
        if job is None:
            return
        if self._db.requeue_rotation(
                job["job_id"],
                error="resuming after key service recovery"):
            print(f"[rotation] requeued failed job {job['job_id']} "
                  f"({job['old_key_id']} -> {job['new_key_id']})")

    async def _drive_job(self, job_id: str):
        while not self._stop.is_set():
            job = self._db.get_rotation(job_id)
            if job is None or job["state"] in ("completed", "failed"):
                return
            if job["state"] == "retrying":
                # 退避等待；等待期间上传/下载照常，结束后重新尝试
                wait = max(0.0, (job["next_retry_at"] or 0) - time.time())
                if wait > 0:
                    await asyncio.sleep(min(wait, POLL_INTERVAL))
                    continue
            try:
                if job["state"] == "migrating":
                    done = await self._migrate(job)
                    if done:
                        self._db.bump_rotation(
                            job_id, state="destroying", attempts=0,
                            clear_next_retry=True, clear_error=True)
                    else:
                        await asyncio.sleep(POLL_INTERVAL)
                elif job["state"] == "destroying":
                    await self._destroy(job)
                    return
                elif job["state"] == "retrying":
                    # rewrap 幂等：从 retrying 回到迁移阶段继续
                    self._db.bump_rotation(job_id, state="migrating",
                                           clear_next_retry=True)
            except KeyServiceError as exc:
                if exc.status_code in PERMANENT_KEY_ERRORS:
                    self._db.bump_rotation(
                        job_id, state="failed", permanent=1,
                        error=f"key service rejected rotation: "
                              f"{exc.status_code} {exc.code} {exc.message}")
                    return
                attempts = (job["attempts"] or 0) + 1
                delay = min(RETRY_BASE * (2 ** (attempts - 1)), RETRY_MAX)
                self._db.bump_rotation(
                    job_id, state="retrying", attempts=attempts,
                    next_retry_at=time.time() + delay,
                    error=f"key service unavailable (attempt {attempts}): "
                          f"{exc.code} {exc.message}")
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # 防御：任何意外都落 failed，不静默
                self._db.bump_rotation(job_id, state="failed", permanent=1,
                                       error=f"unexpected: {exc!r}")
                traceback.print_exc()
                return

    async def _migrate(self, job: dict) -> bool:
        """扫描绑定旧 MK 的可读/在途行并 rewrap。True 表示零残留可销毁。

        逐行区分错误：密钥服务暂不可用 -> 抛给上层进入 retrying；某行信封
        永久不可解包（400/404）-> 该行如实标 failed 并继续；旧 MK 已被外部
        销毁（410）-> 剩余依赖行全部不可读，如实标 failed 后继续销毁流程。
        """
        old_key, job_id = job["old_key_id"], job["job_id"]
        processed = 0
        for row in self._db.iter_under_key(old_key):
            latest = self._db.get_rotation(job_id)
            if latest is None or latest["state"] in ("failed", "completed"):
                return False
            # 在途上传分两种：
            #  1) 僵死（超时）-> 判失败，禁止晚发布，解除销毁阻塞
            #  2) 活跃 -> 跳过，本轮先迁移别的；最终成功的上传会在 finalize
            #     时改绑当前新 MK；失败的不会成为可读原片
            if row["status"] == "receiving":
                if time.time() - row["created_at"] > UPLOAD_STALE_SECONDS:
                    self._db.fail_image(
                        row["image_id"],
                        "stale receiving upload during key rotation")
                    self._db.bump_rotation(job_id, failed=1)
                continue
            token = f"{job_id}:{row['image_id']}"
            try:
                res = await self._keys.rewrap(old_key, row["wrapped_dek"], token)
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    # 旧 MK 已被外部销毁：剩余依赖行的信封已不可解包，如实标
                    # failed（下载会返回 409），作业永久失败；没有旧密钥可销毁。
                    n = self._db.fail_unmigratable_rows(
                        old_key,
                        "master key was destroyed before envelope migration")
                    self._db.bump_rotation(
                        job_id, failed=n, state="failed", permanent=1,
                        error=f"old master key {old_key} was destroyed with "
                              f"{n} row(s) still depending on it; those images "
                              "are unreadable")
                    return False
                if exc.status_code in (400, 404):
                    # 该行信封损坏/主密钥 id 不存在：永久不可读，逐行落 failed
                    self._db.fail_image(
                        row["image_id"],
                        f"envelope cannot be migrated: {exc.code} "
                        f"{exc.message}")
                    self._db.bump_rotation(job_id, failed=1)
                    continue
                raise
            # 条件更新：若该行已被 finalize 改绑新 MK，则自然跳过
            if self._db.rewrap_row(row["image_id"], old_key,
                                   res["key_id"], res["wrapped_dek"]):
                self._db.bump_rotation(job_id, migrated=1)
            processed += 1
            if processed % 50 == 0:
                await asyncio.sleep(BATCH_PAUSE)
                self._record_progress(job_id)

        self._record_progress(job_id)
        # 最终核验：在途上传可能在扫描后又落了一行旧 MK，下轮继续补迁到零依赖
        return self._db.count_under_key(old_key, only_migratable=True) == 0

    def _record_progress(self, job_id: str) -> None:
        """如实记录进度：migrated 是已脱离旧 MK 的件数，failed 是轮换期间
        判失败的僵死在途上传；两者都不虚报，重启重扫也不会把进度算高。"""
        job = self._db.get_rotation(job_id)
        if job is None:
            return
        remaining = self._db.count_under_key(job["old_key_id"],
                                             only_migratable=True)
        total = max(job["total"], job["migrated"] + job["failed"] + remaining)
        self._db.set_rotation_progress(job_id, total, job["migrated"])

    async def _verify_readable(self, job: dict):
        """销毁前抽样解包新信封，确认迁移后的原片确实可读。

        只调用密钥服务 unwrap（不读 blob、不接触明文原片）；明文 DEK 仅在本
        协程内短暂存在并立刻丢弃。任何确定性解包失败 -> 永久失败，不销毁旧钥匙。
        """
        if VERIFY_SAMPLE <= 0:
            return
        # 抽样“不再依赖旧 MK”的 ready 行；若历史上多把旧 MK 残留、
        # job.new_key_id 已非当前 MK，这样仍能覆盖真实在库原片。
        rows = self._db.sample_ready_not_under_key(job["old_key_id"],
                                                   limit=VERIFY_SAMPLE)
        for row in rows:
            dek: bytes | None = None
            try:
                dek = await self._keys.unwrap(row["master_key_id"],
                                              row["wrapped_dek"])
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    raise KeyServiceError(
                        410, "migrated_row_unreadable",
                        f"image {row['image_id']} cannot be unwrapped with new "
                        f"master key: {exc.message}")
                raise
            finally:
                dek = None  # 立即丢弃明文 DEK 引用，不进入任何持久结构

    async def _destroy(self, job: dict) -> None:
        old_key, job_id = job["old_key_id"], job["job_id"]
        # 销毁前最后一次核实（防扫描窗口内的迟到行）：ready 与 receiving 都必须
        # 已不依赖旧 MK，否则回到迁移阶段继续补迁。
        remaining = self._db.count_under_key(old_key, only_migratable=True)
        if remaining != 0:
            self._db.set_rotation_progress(
                job_id, max(job["total"], job["migrated"] + remaining),
                job["migrated"])
            self._db.bump_rotation(job_id, state="migrating")
            return
        # 核实新信封可读（抽样 unwrap；失败则不销毁）
        await self._verify_readable(job)
        # 销毁；回执丢失时 KeyClient 内部以只读 status 核实，不提前报完成
        await self._keys.destroy_master(old_key)
        # 二次核实：密钥服务视角确实 destroyed
        status = await self._keys.master_status()
        states = {k["key_id"]: k["state"] for k in status.get("keys", [])}
        if states.get(old_key) != "destroyed":
            raise KeyServiceError(503, "destroy_not_verified",
                                  "destroy receipt cannot be verified")
        # 销毁已核实后才报 completed；计数如实反映实际迁移与判失败结果。
        # remaining=0 时，除轮换期间判失败的行外，其余原片都已脱离旧 MK
        #（含 finalize 时自动改绑的跨轮换在途上传），故 migrated 按差额核算。
        total = max(job["total"], job["migrated"] + job["failed"])
        migrated = max(0, total - job["failed"])
        self._db.mark_destroy_verified(
            job_id, migrated=migrated, failed=job["failed"])

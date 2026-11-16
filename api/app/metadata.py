"""API 元数据库（SQLite，WAL）。

只存：原片元数据、密文 blob 路径、信封 DEK（密文）、主密钥 id、状态。
绝不存：明文 DEK、明文原片、主密钥材料。

轮换作业状态：
  migrating / destroying / retrying   非终态，进程重启后由后台线程接续
  completed                          迁移与销毁均已核实
  failed                             终态；permanent=1 表示不可自动重试，
                                     permanent=0 表示旧版本遗留的瞬时失败，
                                     启动/对账时会自动重新入队

retrying 表示密钥服务暂时不可用：保留 last error、attempts 与 next_retry_at，
密钥服务恢复后自动继续迁移；旧依赖清除前不会被当作“已完成”。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterator

ROTATION_STATES = ("migrating", "destroying", "retrying", "completed", "failed")

IMAGES_SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id        TEXT PRIMARY KEY,
    filename        TEXT,
    content_type    TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('receiving','ready','failed')),
    master_key_id   TEXT NOT NULL,
    wrapped_dek     TEXT NOT NULL,           -- 十六进制信封，始终为密文
    blob_path       TEXT NOT NULL,
    plain_size      INTEGER,
    enc_size        INTEGER,
    sha256          TEXT,
    idem_token      TEXT UNIQUE,
    error           TEXT,
    created_at      REAL NOT NULL,
    finalized_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_images_mk ON images(master_key_id);
CREATE INDEX IF NOT EXISTS idx_images_status ON images(status);
"""

ROTATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS rotation_jobs (
    job_id          TEXT PRIMARY KEY,
    state           TEXT NOT NULL CHECK (state IN
                        ('migrating','destroying','retrying',
                         'completed','failed')),
    old_key_id      TEXT NOT NULL,
    new_key_id      TEXT NOT NULL,
    total           INTEGER NOT NULL DEFAULT 0,
    migrated        INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_retry_at   REAL,
    permanent       INTEGER NOT NULL DEFAULT 0,
    destroy_verified INTEGER NOT NULL DEFAULT 0,
    started_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    finished_at     REAL
);
"""

TERMINAL_STATES = ("completed", "failed")
# 旧版本库可能缺列或 CHECK 不含 retrying；启动时按需重建该表
ROTATION_COLUMNS_ALL = (
    "job_id", "state", "old_key_id", "new_key_id", "total", "migrated",
    "failed", "error", "attempts", "next_retry_at", "permanent",
    "destroy_verified", "started_at", "updated_at", "finished_at")


class MetadataDB:
    """每线程独立连接（SQLite 连接不跨线程复用），写操作串行化。"""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._write_lock = threading.RLock()
        self._local = threading.local()
        conn = self._connect()
        conn.executescript(IMAGES_SCHEMA)
        self._init_rotation_schema(conn)
        conn.commit()
        conn.close()

    def _init_rotation_schema(self, conn: sqlite3.Connection) -> None:
        """建表；旧库（缺 retrying 状态或新列）就地迁移，保留历史作业。"""
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='rotation_jobs'").fetchone()
        if row is None:
            conn.executescript(ROTATION_SCHEMA)
            return
        cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(rotation_jobs)").fetchall()}
        has_state = "retrying" in (row["sql"] or "")
        if has_state and all(c in cols for c in ROTATION_COLUMNS_ALL):
            return
        # SQLite 不能改 CHECK：重建表并按列名拷贝可迁移字段。
        # 旧库里的 failed 作业是“瞬时故障被误判终态”的遗留，permanent 置 0，
        # 启动/运行期会自动重新入队接续。
        copied = ", ".join(
            c if c in cols else {
                "attempts": "0",
                "next_retry_at": "NULL",
                "permanent": "0",
                "destroy_verified": "0",
            }[c] for c in ROTATION_COLUMNS_ALL)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ALTER TABLE rotation_jobs RENAME TO rotation_jobs_old")
            conn.execute(ROTATION_SCHEMA)
            conn.execute(
                f"INSERT INTO rotation_jobs ({', '.join(ROTATION_COLUMNS_ALL)}) "
                f"SELECT {copied} FROM rotation_jobs_old")
            conn.execute("DROP TABLE rotation_jobs_old")
            conn.commit()
        except Exception:
            conn.rollback()   # 迁移失败不得留下半张表
            raise

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    # ---- 原片 -----------------------------------------------------------
    def create_image(self, image_id: str, filename: str | None,
                     content_type: str | None, master_key_id: str,
                     wrapped_dek: str, blob_path: str,
                     idem_token: str | None) -> str:
        with self._write_lock:
            if idem_token:
                existing = self.conn.execute(
                    "SELECT image_id FROM images WHERE idem_token=?",
                    (idem_token,)).fetchone()
                if existing:
                    return existing["image_id"]
            now = time.time()
            self.conn.execute(
                "INSERT INTO images (image_id, filename, content_type, status, "
                "master_key_id, wrapped_dek, blob_path, idem_token, created_at) "
                "VALUES (?,?,?, 'receiving', ?,?,?,?,?)",
                (image_id, filename, content_type, master_key_id,
                 wrapped_dek, blob_path, idem_token, now))
            self.conn.commit()
            return image_id

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE image_id=?", (image_id,)).fetchone()
        return dict(row) if row else None

    def get_by_token(self, idem_token: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE idem_token=?", (idem_token,)).fetchone()
        return dict(row) if row else None

    def finalize_image(self, image_id: str, plain_size: int, enc_size: int,
                       sha256: str) -> bool:
        """仅在行仍为 receiving 时发布 ready。

        防止与轮换线程竞态：若迁移已把该行判失败（如旧密钥被外部销毁、
        僵死超时等），这里绝不能再把它发布成可读原片。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='ready', plain_size=?, enc_size=?, "
                "sha256=?, finalized_at=?, error=NULL "
                "WHERE image_id=? AND status='receiving'",
                (plain_size, enc_size, sha256, time.time(), image_id))
            self.conn.commit()
            return cur.rowcount > 0

    def fail_image(self, image_id: str, error: str) -> None:
        with self._write_lock:
            # 失败行释放幂等令牌，允许客户端用同一令牌重新发起上传
            self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=?, "
                "idem_token=NULL WHERE image_id=?",
                (error[:500], time.time(), image_id))
            self.conn.commit()

    def list_images(self, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT image_id, filename, status, master_key_id, plain_size, "
            "sha256, created_at, finalized_at FROM images "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def distinct_key_ids(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT master_key_id FROM images").fetchall()
        return [r["master_key_id"] for r in rows]

    def count_under_key(self, key_id: str,
                        only_migratable: bool = False) -> int:
        sql = "SELECT COUNT(*) AS n FROM images WHERE master_key_id=?"
        if only_migratable:
            # 仅统计会阻塞销毁的行：ready（必须 rewrap）与在途 receiving；
            # failed 行永不会被下载，无需有效信封，不阻塞销毁。
            sql += " AND status IN ('ready','receiving')"
        return self.conn.execute(sql, (key_id,)).fetchone()["n"]

    def count_under_other_key(self, key_id: str) -> int:
        """仍有 ready/receiving 行绑定非当前 MK 的件数（=未清除的旧依赖）。"""
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM images WHERE master_key_id<>? "
            "AND status IN ('ready','receiving')", (key_id,)).fetchone()["n"]

    def rows_under_other_key(self, key_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT DISTINCT master_key_id FROM images WHERE master_key_id<>? "
            "AND status IN ('ready','receiving')", (key_id,)).fetchall()
        return [r["master_key_id"] for r in rows]

    def iter_under_key(self, key_id: str) -> Iterator[dict]:
        rows = self.conn.execute(
            "SELECT * FROM images WHERE master_key_id=? "
            "AND status IN ('ready','receiving') ORDER BY created_at",
            (key_id,)).fetchall()
        for r in rows:
            yield dict(r)

    def sample_ready_not_under_key(self, key_id: str,
                                   limit: int = 50) -> list[dict]:
        """抽样“不再依赖旧 MK”的 ready 行，销毁前逐个核实其信封可解包。

        覆盖最早与最新两端；若已无其他 ready 行则返回空（无可核实对象）。
        """
        rows = self.conn.execute(
            "SELECT * FROM images WHERE status='ready' AND master_key_id<>? "
            "ORDER BY created_at", (key_id,)).fetchall()
        items = [dict(r) for r in rows]
        if limit <= 0 or limit >= len(items):
            return items
        head = limit // 2
        return items[:head] + items[-(limit - head):]

    def fail_unmigratable_rows(self, key_id: str, error: str) -> int:
        """旧 MK 已被销毁时，把仍依赖它的 ready 行如实标 failed。

        这些原片的信封已无法解包（密钥材料已零覆写），不再可读；标 failed
        既符合事实，也避免它们永久阻塞后续轮换与销毁流程。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=? "
                "WHERE master_key_id=? AND status IN ('ready','receiving')",
                (error[:500], time.time(), key_id))
            self.conn.commit()
            return cur.rowcount

    def rewrap_row(self, image_id: str, expect_old_key: str,
                   new_key_id: str, new_wrapped: str) -> bool:
        """条件更新：仅当该行仍绑定旧 MK 时改包，返回是否实际更新。

        这样迁移与"迟到的在途上传最终化"互不覆盖：后者若已自行改绑新 MK，
        迁移跳过它即可。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET master_key_id=?, wrapped_dek=? "
                "WHERE image_id=? AND master_key_id=?",
                (new_key_id, new_wrapped, image_id, expect_old_key))
            self.conn.commit()
            return cur.rowcount > 0

    def mark_stale_receiving_failed(self) -> int:
        """进程重启后，所有 receiving 都是上次崩溃的在途上传，
        不允许晚发布（防止它依赖已销毁的旧 MK 才完成）。"""
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='failed', "
                "error='interrupted by service restart', finalized_at=? "
                "WHERE status='receiving'", (time.time(),))
            self.conn.commit()
            return cur.rowcount

    # ---- 轮换作业 -------------------------------------------------------
    def active_rotation(self) -> dict | None:
        """优先返回正在执行的作业，其次返回待重试/待接续的作业。

        retrying 属于非终态：它既会被后台线程自动接续，也会阻塞新轮换。
        """
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE state NOT IN ('completed','failed') "
            "ORDER BY CASE state WHEN 'migrating' THEN 0 WHEN 'destroying' THEN 1 "
            "ELSE 2 END, started_at LIMIT 1").fetchone()
        return dict(row) if row else None

    def resumable_rotations(self) -> list[dict]:
        """需要在启动后自动接续的作业：非终态，或旧的“瞬时失败”终态。

        permanent=1 表示已确认不可自动恢复（如旧 MK 已被外部销毁），不再重试。
        """
        rows = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE state NOT IN ('completed','failed') "
            "OR (state='failed' AND permanent=0) ORDER BY started_at").fetchall()
        return [dict(r) for r in rows]

    def clear_retry_backoff(self) -> int:
        """进程刚启动时清除退避等待，让 retrying 作业立即重试（无需等满 30s）。

        重启本身就说明运维在介入；attempts 保留用于排障，不清零。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE rotation_jobs SET next_retry_at=NULL, updated_at=? "
                "WHERE state='retrying'", (time.time(),))
            self.conn.commit()
            return cur.rowcount

    def next_failed_rotation(self) -> dict | None:
        """最早一个可自动接续的失败作业（同一时刻只续作一个）。"""
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE state='failed' AND permanent=0 "
            "ORDER BY started_at LIMIT 1").fetchone()
        return dict(row) if row else None

    def pending_dependency_rotation(self) -> dict | None:
        """在旧依赖清除（或旧作业被接续完成）前应阻塞新轮换的作业。

        判定条件：
          * 仍有 ready/receiving 行绑定其旧 MK（任何状态的作业都算）；
          * 或作业尚未到 completed（非终态，或可自动接续的 failed）；
        permanent=1 且已无依赖的作业（旧 MK 被外部销毁、行已如实判失败）
        不会再自动续作，也不阻塞新轮换。
        """
        rows = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at").fetchall()
        for job in (dict(r) for r in rows):
            remaining = self.count_under_key(job["old_key_id"],
                                             only_migratable=True)
            if (job["state"] != "completed"
                    and (remaining > 0 or job["state"] != "failed"
                         or not job["permanent"])):
                return {
                    "job_id": job["job_id"], "state": job["state"],
                    "old_key_id": job["old_key_id"],
                    "new_key_id": job["new_key_id"],
                    "permanent": job["permanent"],
                    "remaining": remaining,
                    "error": job["error"],
                }
        return None

    def create_rotation(self, old_key_id: str, new_key_id: str,
                        total: int) -> str:
        with self._write_lock:
            # 并发入口保护：另一请求可能刚通过 API 层检查；这里在同一把锁内
            # 复核“无未完成作业”，保证同一时刻只有一个作业被建立。
            if self.active_rotation() is not None:
                raise RuntimeError("rotation already in progress")
            if self.next_failed_rotation() is not None:
                raise RuntimeError("a failed rotation is pending resume")
            job_id = "rot-" + uuid.uuid4().hex
            now = time.time()
            self.conn.execute(
                "INSERT INTO rotation_jobs (job_id, state, old_key_id, "
                "new_key_id, total, migrated, failed, started_at, updated_at) "
                "VALUES (?, 'migrating', ?,?,?, 0, 0, ?, ?)",
                (job_id, old_key_id, new_key_id, total, now, now))
            self.conn.commit()
            return job_id

    def requeue_rotation(self, job_id: str, error: str | None = None) -> bool:
        """把 failed 作业改回 migrating，用于密钥服务恢复后的自动接续。"""
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE rotation_jobs SET state='migrating', permanent=0, "
                "next_retry_at=NULL, error=?, finished_at=NULL, updated_at=? "
                "WHERE job_id=? AND state='failed' AND permanent=0",
                (error, time.time(), job_id))
            self.conn.commit()
            return cur.rowcount > 0

    def rotation_for_key(self, key_id: str) -> dict | None:
        """最近一次以该 MK 为旧密钥的轮换作业（用于在途上传的改绑判断）。"""
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE old_key_id=? "
            "ORDER BY started_at DESC LIMIT 1", (key_id,)).fetchone()
        return dict(row) if row else None

    def has_rotation_for(self, old_key_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
            (old_key_id,)).fetchone() is not None

    def get_rotation(self, job_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def latest_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def bump_rotation(self, job_id: str, migrated: int = 0, failed: int = 0,
                      state: str | None = None, error: str | None = None,
                      attempts: int | None = None,
                      next_retry_at: float | None = None,
                      clear_next_retry: bool = False,
                      permanent: int | None = None,
                      clear_error: bool = False) -> None:
        """计数只在确实发生迁移/判失败时累加（rewrap_row 条件更新成功才算），
        因此重启后重扫也不会重复计数、进度如实。"""
        with self._write_lock:
            sets = ["updated_at=?"]
            params: list[Any] = [time.time()]
            if migrated:
                sets.append("migrated = migrated + ?")
                params.append(migrated)
            if failed:
                sets.append("failed = failed + ?")
                params.append(failed)
            if state:
                sets.append("state=?")
                params.append(state)
            if clear_error:
                sets.append("error=NULL")
            elif error is not None:
                sets.append("error=?")
                params.append(error[:500])
            if attempts is not None:
                sets.append("attempts=?")
                params.append(attempts)
            if clear_next_retry:
                sets.append("next_retry_at=NULL")
            elif next_retry_at is not None:
                sets.append("next_retry_at=?")
                params.append(next_retry_at)
            if permanent is not None:
                sets.append("permanent=?")
                params.append(permanent)
            if state in TERMINAL_STATES:
                sets.append("finished_at=?")
                params.append(time.time())
            elif state is not None:
                sets.append("finished_at=NULL")
            params.append(job_id)
            self.conn.execute(
                f"UPDATE rotation_jobs SET {', '.join(sets)} WHERE job_id=?",
                params)
            self.conn.commit()

    def set_rotation_progress(self, job_id: str, total: int,
                              migrated: int) -> None:
        """如实记录迁移进度（migrated = 已不再依赖旧 MK 的可读/在途行数）。"""
        with self._write_lock:
            self.conn.execute(
                "UPDATE rotation_jobs SET total=?, migrated=?, updated_at=? "
                "WHERE job_id=?", (total, migrated, time.time(), job_id))
            self.conn.commit()

    def mark_destroy_verified(self, job_id: str, migrated: int,
                              failed: int) -> None:
        """销毁已由密钥服务只读核实后才调用：据此写入终态与最终计数。

        total = 迁移成功 + 轮换期间判失败的僵死在途上传（两者均不再阻塞
        销毁）；migrated 只计真正脱离旧 MK 的行，不把 failed 混入成功数。
        零原片轮换时 total=0，completed 视图仍显示 100%。
        """
        total = migrated + failed
        with self._write_lock:
            self.conn.execute(
                "UPDATE rotation_jobs SET state='completed', total=?, migrated=?, "
                "failed=?, destroy_verified=1, error=NULL, next_retry_at=NULL, "
                "finished_at=?, updated_at=? WHERE job_id=?",
                (total, migrated, failed, time.time(), time.time(), job_id))
            self.conn.commit()

    def close(self):
        c = getattr(self._local, "conn", None)
        if c:
            c.close()

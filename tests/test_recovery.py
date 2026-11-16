"""故障恢复接续：密钥服务短暂不可用后的轮换作业续作。

覆盖本次修复的关键语义：
  R1 密钥服务 rewrap 持续 503：作业进入 retrying（非终态），不误判 failed；
     期间拒绝新轮换，但上传/下载照常，密文正文不变。
  R2 密钥服务恢复：作业自动接续并完成，旧 MK 在零依赖后销毁，作业如实计数。
  R3 API 重启后 failed 遗留作业（permanent=0）自动接续到完成。
  R4 仍有原片依赖旧 MK 的失败作业会阻塞新轮换（元数据层直接验证）。
  R5 旧库结构迁移：缺 retrying/新列的 rotation_jobs 可平滑升级并保留作业。
"""
from __future__ import annotations

import importlib.util
import sqlite3
import time
import uuid
from pathlib import Path

import pytest

from conftest import _download, _key_headers, _upload, _wait_rotation

ROOT = Path(__file__).resolve().parents[1]


def _load_metadata_module():
    """独立加载 api/app/metadata.py（不触发 FastAPI 应用初始化）。"""
    spec = importlib.util.spec_from_file_location(
        f"metadata_under_test_{uuid.uuid4().hex}",
        ROOT / "api" / "app" / "metadata.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _start_rotation(client):
    return client.post("/rotations", json={"confirm": True})


def _wait_state(client, job_id: str, states: tuple[str, ...],
                timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/rotations/{job_id}").json()
        if job["state"] in states:
            return job
        time.sleep(0.2)
    raise AssertionError(f"job never reached {states}: "
                         f"{client.get(f'/rotations/{job_id}').json()}")


def _key_states(client) -> dict:
    status = client.get("/keys/status").json()
    return {k["key_id"]: k["state"] for k in status["keys"]}


def test_key_outage_retries_then_resumes_and_preserves_traffic(stack):
    client, kc = stack["client"], stack["key_client"]
    payloads = {f"outage-{i}": f"body-{i}-".encode() * 5000 for i in range(3)}
    for image_id, data in payloads.items():
        assert _upload(client, data, image_id=image_id).status_code == 201
    old_key = client.get("/images/outage-0/meta").json()["master_key_id"]
    blob_files = {p.name: p.read_bytes() for p in stack["blob_dir"].iterdir()}

    # 密钥服务只对 rewrap 故障注入：轮换能起步，迁移阶段持续 503
    stack["keys"].set_env(KEY_FAIL_OPS="rewrap")
    resp = _start_rotation(client)
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]

    # 副本进入 retrying（非终态），而不是被误判 failed
    job = _wait_state(client, job_id, ("retrying",), timeout=30)
    assert job["state"] == "retrying"
    assert job["attempts"] >= 1
    assert "key service unavailable" in (job["error"] or "")
    assert job["finished_at"] is None

    # 旧依赖未清除前拒绝新轮换
    blocked = _start_rotation(client)
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "rotation_in_progress"
    assert blocked.json()["detail"]["state"] == "retrying"

    # 恢复期间原片仍可入仓、下载；已有密文正文逐字节不变
    new_payload = b"ingested-during-outage" * 100
    assert _upload(client, new_payload, image_id="during-outage").status_code == 201
    for image_id, data in payloads.items():
        assert _download(client, image_id) == data
    assert _download(client, "during-outage") == new_payload
    after = {p.name: p.read_bytes() for p in stack["blob_dir"].iterdir()}
    # 既有原片密文正文逐字节未变（新入仓的那件除外）
    assert {k: v for k, v in after.items() if k in blob_files} == blob_files
    assert "during-outage.msef" in after

    # 密钥服务恢复（去掉注入）：作业自动接续到 completed
    stack["keys"].set_env(KEY_FAIL_OPS="")
    done = _wait_rotation(client, job_id, timeout=120)
    assert done["state"] == "completed", done
    assert done["destroy_verified"] == 1
    assert done["failed"] == 0
    # 轮换起步时旧 MK 下 3 件；故障期间新入仓的 1 件直接绑定新 MK，不计入迁移
    assert done["migrated"] == done["total"] == 3
    assert done["progress_percent"] == 100.0

    # 旧 MK 确认销毁，且所有原片仍逐字节可读、正文未重写
    states = _key_states(client)
    assert states[old_key] == "destroyed"
    after = {p.name: p.read_bytes() for p in stack["blob_dir"].iterdir()}
    assert {k: v for k, v in after.items() if k in blob_files} == blob_files
    for image_id, data in payloads.items():
        assert _download(client, image_id) == data
    assert _download(client, "during-outage") == new_payload


def test_retrying_job_resumes_after_api_restart(stack):
    """密钥服务持续不可用时重启 API：retrying 作业立即重试并接续完成。"""
    client, kc = stack["client"], stack["key_client"]
    payload = b"retrying-across-restart" * 500
    assert _upload(client, payload, image_id="retry-restart-1").status_code == 201
    old_key = client.get("/images/retry-restart-1/meta").json()["master_key_id"]

    stack["keys"].set_env(KEY_FAIL_OPS="rewrap")
    job_id = _start_rotation(client).json()["job_id"]
    _wait_state(client, job_id, ("retrying",), timeout=30)

    # API 重启（密钥服务仍故障）：作业保持非终态并继续尝试
    stack["api"].restart()
    job = _wait_state(client, job_id, ("retrying",), timeout=30)
    assert job["state"] == "retrying" and job["finished_at"] is None
    # 期间拒绝新轮换，但原片仍可读
    assert _start_rotation(client).status_code == 409
    assert _download(client, "retry-restart-1") == payload

    # 密钥服务恢复后自动接续到 completed
    stack["keys"].set_env(KEY_FAIL_OPS="")
    done = _wait_rotation(client, job_id, timeout=120)
    assert done["state"] == "completed", done
    assert done["destroy_verified"] == 1 and done["failed"] == 0
    assert _key_states(client)[old_key] == "destroyed"
    assert _download(client, "retry-restart-1") == payload


def test_failed_legacy_job_resumes_after_api_restart(stack):
    """修复前的遗留失败作业：API 重启后自动接续并完成销毁。"""
    client, kc = stack["client"], stack["key_client"]
    payload = b"legacy-failed-job" * 1000
    assert _upload(client, payload, image_id="legacy-1").status_code == 201
    old_key = client.get("/images/legacy-1/meta").json()["master_key_id"]
    blob_file = next(stack["blob_dir"].iterdir())
    blob_before = blob_file.read_bytes()

    # 模拟旧版本：MK 已在密钥服务切换，但本地作业被误判为终态 failed
    rot = kc.post("/internal/master/rotate", headers=_key_headers()).json()
    assert rot["old_key_id"] == old_key
    new_key = rot["new_key_id"]
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    conn.execute(
        "INSERT INTO rotation_jobs (job_id, state, old_key_id, new_key_id, total, "
        "migrated, failed, error, attempts, permanent, destroy_verified, "
        "started_at, updated_at, finished_at) "
        "VALUES (?, 'failed', ?, ?, 1, 0, 0, 'key service error after retries', "
        "6, 0, 0, ?, ?, ?)",
        ("rot-legacy", old_key, new_key, time.time() - 10, time.time() - 5,
         time.time() - 5))
    conn.commit()
    conn.close()

    stack["api"].restart()
    done = _wait_rotation(client, "rot-legacy", timeout=90)
    assert done["state"] == "completed", done
    assert done["migrated"] == 1 and done["failed"] == 0
    assert done["destroy_verified"] == 1
    assert _key_states(client)[old_key] == "destroyed"
    assert blob_file.read_bytes() == blob_before
    assert _download(client, "legacy-1") == payload
    # 接续完成后允许新轮换
    job = _start_rotation(client)
    assert job.status_code == 202, job.text
    assert _wait_rotation(client, job.json()["job_id"])["state"] == "completed"


def test_pending_old_key_dependency_blocks_new_rotation_offline(tmp_path):
    """元数据层：仍有 ready 行依赖旧 MK 的 failed 作业必须阻塞新轮换。"""
    mod = _load_metadata_module()
    db = mod.MetadataDB(str(tmp_path / "metadata.db"))
    old_key, new_key = "mk-old", "mk-new"
    job_id = db.create_rotation(old_key, new_key, total=1)
    db.create_image("img-1", None, None, old_key, "00" * 64,
                    str(tmp_path / "img-1.msef"), None)
    db.finalize_image("img-1", 3, 60, "0" * 64)
    db.bump_rotation(job_id, state="failed", permanent=0,
                     error="key service error after retries")

    pending = db.pending_dependency_rotation()
    assert pending is not None
    assert pending["job_id"] == job_id
    assert pending["remaining"] == 1

    # 旧依赖仍在：即便作业是 failed 终态，也必须能被重新入队接续
    assert db.requeue_rotation(job_id) is True
    assert db.active_rotation()["state"] == "migrating"

    # 迁移完成后（行脱离旧 MK）不再阻塞，但永久失败（permanent=1）不自动重试
    assert db.rewrap_row("img-1", old_key, new_key, "11" * 64)
    db.bump_rotation(job_id, state="failed", permanent=1, error="unexpected")
    assert db.pending_dependency_rotation() is None
    assert db.next_failed_rotation() is None
    assert db.requeue_rotation(job_id) is False
    db.close()


def test_legacy_rotation_schema_is_migrated_in_place(tmp_path):
    """旧库（CHECK 不含 retrying、无新列）启动时就地升级，历史作业保留。"""
    db_path = tmp_path / "metadata.db"
    conn = sqlite3.connect(db_path)
    conn.executescript("""
    CREATE TABLE rotation_jobs (
        job_id TEXT PRIMARY KEY,
        state TEXT NOT NULL CHECK (state IN ('migrating','destroying',
                                              'completed','failed')),
        old_key_id TEXT NOT NULL,
        new_key_id TEXT NOT NULL,
        total INTEGER NOT NULL DEFAULT 0,
        migrated INTEGER NOT NULL DEFAULT 0,
        failed INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        started_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        finished_at REAL
    );
    INSERT INTO rotation_jobs (job_id, state, old_key_id, new_key_id, total,
        migrated, failed, error, started_at, updated_at, finished_at)
    VALUES ('rot-old','failed','mk-a','mk-b',2,1,0,'timeout',1,2,2);
    """)
    conn.commit()
    conn.close()

    mod = _load_metadata_module()
    db = mod.MetadataDB(str(db_path))
    job = db.get_rotation("rot-old")
    assert job["state"] == "failed"
    assert job["permanent"] == 0          # 瞬时失败遗留 -> 允许自动接续
    assert job["attempts"] == 0 and job["destroy_verified"] == 0
    assert job["migrated"] == 1 and job["total"] == 2
    # retrying 现在是合法状态（旧 CHECK 升级成功）
    db.bump_rotation("rot-old", state="retrying", attempts=1)
    assert db.get_rotation("rot-old")["state"] == "retrying"
    assert db.active_rotation()["job_id"] == "rot-old"
    db.close()

"""Kiểm thử ShareStore (không cần FTPS/SSH, chạy được trên Windows)."""
import json
import threading

import pytest

from securetransfer.shares import ShareError, ShareStore


@pytest.fixture
def env(tmp_path):
    now = [1000.0]
    return ShareStore(str(tmp_path / "data" / "shares.json"), clock=lambda: now[0]), now, tmp_path


def _status(fn, *args):
    with pytest.raises(ShareError) as info:
        fn(*args)
    return info.value


def test_counts_downloads_and_stores_only_hash(env):
    store, _, tmp = env
    token, share = store.create("a.txt", "INTERNAL", "partner", "bob", 30, 2)
    assert store.consume(token)["downloads"] == 1
    assert store.consume(token)["downloads"] == 2
    assert _status(store.consume, token).status == 410
    assert token not in (tmp / "data" / "shares.json").read_text(encoding="utf-8")
    assert share["id"] in json.dumps(store.get(token))


def test_expiry_revoke_and_unknown(env):
    store, now, _ = env
    token, _ = store.create("a.txt", "INTERNAL", "partner", "bob", 30, 5)
    now[0] += 30 * 60 - 1
    store.consume(token)
    now[0] += 2
    assert "hết hạn" in str(_status(store.consume, token))
    t2, _ = store.create("b.txt", "INTERNAL", "partner", "bob", 30, 5)
    store.revoke(t2)
    assert "thu hồi" in str(_status(store.consume, t2))
    assert _status(store.consume, "khong-co").status == 404


def test_refund_and_persistence(env):
    store, now, tmp = env
    token, _ = store.create("a.txt", "INTERNAL", "partner", "bob", 30, 1)
    store.consume(token)
    store.refund(token)
    again = ShareStore(str(tmp / "data" / "shares.json"), clock=lambda: now[0])
    assert again.consume(token)["downloads"] == 1


def test_rejects_bad_limits(env):
    store, _, _ = env
    for minutes, count in [(0, 3), (30, 0), (10**6, 3), (30, 10**4)]:
        with pytest.raises(ValueError):
            store.create("a.txt", "INTERNAL", "partner", "bob", minutes, count)


def test_concurrent_downloads_never_exceed_limit(env):
    store, _, _ = env
    token, _ = store.create("a.txt", "INTERNAL", "partner", "bob", 30, 5)
    passed = []

    def worker():
        try:
            store.consume(token)
        except ShareError:
            return
        passed.append(1)

    threads = [threading.Thread(target=worker) for _ in range(40)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(passed) == 5


def test_version_is_stored_with_the_share(env):
    store, _, _ = env
    token, share = store.create("a.txt", "INTERNAL", "partner", "bob", 30, 1, version="abc123")
    assert share["version"] == "abc123" and store.get(token)["version"] == "abc123"
    token2, _ = store.create("b.txt", "INTERNAL", "partner", "bob", 30, 1)
    assert store.get(token2)["version"] == ""

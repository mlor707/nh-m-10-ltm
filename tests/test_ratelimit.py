import pytest

from securetransfer.ratelimit import FailureLimiter, LoginThrottle


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


def make(max_failures=3, window=60, lockout=120):
    c = Clock()
    return c, FailureLimiter(max_failures, window, lockout, clock=c)


def test_locks_after_threshold_and_reports_retry_after():
    c, lim = make()
    assert [lim.record_failure("k") for _ in range(3)] == [False, False, True]
    assert lim.retry_after("k") == 120
    c.advance(100.2)
    assert lim.retry_after("k") == 20                 # làm tròn lên
    c.advance(30)
    assert lim.retry_after("k") == 0                  # hết khóa


def test_failures_outside_window_do_not_count():
    c, lim = make()
    lim.record_failure("k"); lim.record_failure("k")
    c.advance(61)                                     # hai lần đầu đã quá cửa sổ
    assert lim.record_failure("k") is False
    assert lim.retry_after("k") == 0


def test_after_lockout_counter_starts_fresh():
    c, lim = make()
    for _ in range(3): lim.record_failure("k")
    c.advance(121)
    assert lim.record_failure("k") is False           # không bị khóa lại ngay từ lần sai đầu tiên
    assert lim.retry_after("k") == 0


def test_keys_are_independent_and_reset_works():
    c, lim = make()
    for _ in range(3): lim.record_failure("a")
    assert lim.retry_after("a") > 0 and lim.retry_after("b") == 0
    lim.reset("a")
    assert lim.retry_after("a") == 0


def test_disabled_when_max_is_zero():
    c, lim = make(max_failures=0)
    for _ in range(50): assert lim.record_failure("k") is False
    assert lim.retry_after("k") == 0


def test_memory_is_bounded_when_flooded_with_random_names():
    c = Clock()
    lim = FailureLimiter(5, 60, 60, clock=c, max_entries=100)
    for i in range(1000):
        lim.record_failure(f"user{i}")
    assert len(lim._entries) <= 100


def test_throttle_pair_lock_does_not_affect_other_ip_or_user():
    c = Clock()
    t = LoginThrottle(max_failures=3, window=60, lockout=60, clock=c)
    for _ in range(3): t.failure("1.1.1.1", "alice")
    assert t.blocked("1.1.1.1", "alice") > 0
    assert t.blocked("2.2.2.2", "alice") == 0         # IP khác vẫn thử được (chưa chạm ngưỡng theo tên)
    assert t.blocked("1.1.1.1", "bob") == 0


def test_throttle_username_is_normalised():
    c = Clock()
    t = LoginThrottle(max_failures=3, window=60, lockout=60, clock=c)
    for name in ("Alice", "ALICE", " alice "): t.failure("1.1.1.1", name)
    assert t.blocked("1.1.1.1", "alice") > 0


def test_throttle_distributed_guessing_hits_per_user_limit():
    c = Clock()
    t = LoginThrottle(max_failures=3, window=60, lockout=60, clock=c)   # ngưỡng theo tên = 12
    locked = [t.failure(f"10.0.0.{i}", "alice") for i in range(12)]     # mỗi IP chỉ sai 1 lần
    assert locked[-1] is True and not any(locked[:-1])
    assert t.blocked("10.9.9.9", "alice") > 0         # IP mới tinh cũng bị chặn


def test_success_clears_pair_counter_only():
    c = Clock()
    t = LoginThrottle(max_failures=3, window=60, lockout=60, clock=c)
    t.failure("1.1.1.1", "alice"); t.failure("1.1.1.1", "alice")
    t.success("1.1.1.1", "alice")
    assert t.failure("1.1.1.1", "alice") is False     # đếm lại từ đầu
    assert t.blocked("1.1.1.1", "alice") == 0


def test_locked_even_with_correct_password_is_caller_responsibility():
    """blocked() phải được gọi TRƯỚC khi xác thực; ở đây chỉ kiểm tra nó giữ trạng thái khóa."""
    c = Clock()
    t = LoginThrottle(max_failures=2, window=60, lockout=60, clock=c)
    t.failure("ip", "alice"); t.failure("ip", "alice")
    c.advance(30)
    assert t.blocked("ip", "alice") == 30

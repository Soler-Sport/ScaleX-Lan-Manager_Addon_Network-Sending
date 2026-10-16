"""The injector must leave a freshly started CHITUBOX Pro alone: injecting
goo_hook.dll 1-5 s after launch made it die with fast-fail 0xC0000409
(2026-10-16), so only processes older than INJECT_MIN_PROCESS_AGE_SEC are
touched."""
import os

from chitu_send import hook_injector


def test_young_process_is_not_ready_and_old_one_is():
    ages = {10: 3.0, 11: 45.0}
    ready = hook_injector._pids_ready_for_injection({10, 11}, set(), {}, ages.get, now=1000.0)

    assert ready == [11]


def test_already_attempted_pids_are_skipped():
    ready = hook_injector._pids_ready_for_injection({11}, {11}, {}, lambda pid: 99.0, now=1000.0)

    assert ready == []


def test_unknown_age_falls_back_to_time_since_first_seen():
    first_seen = {}
    unknown = lambda pid: None

    assert hook_injector._pids_ready_for_injection({5}, set(), first_seen, unknown, now=1000.0) == []
    assert first_seen == {5: 1000.0}
    assert hook_injector._pids_ready_for_injection({5}, set(), first_seen, unknown, now=1000.0 + 31) == [5]


def test_custom_min_age_is_honoured():
    ready = hook_injector._pids_ready_for_injection({1}, set(), {}, lambda pid: 5.0, now=0.0, min_age=2.0)

    assert ready == [1]


def test_process_age_of_this_process_is_small_and_positive():
    age = hook_injector._process_age_sec(os.getpid())

    assert age is not None and 0.0 <= age < 3600


def test_process_age_of_a_dead_pid_is_none():
    assert hook_injector._process_age_sec(0x7FFFFFF0) is None

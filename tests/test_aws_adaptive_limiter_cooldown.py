"""A throttled endpoint pauses new requests briefly; other endpoints and other errors do not."""
import threading

import pytest
from botocore.exceptions import ClientError

from peaso.collectors import aws_request_pool as pool


def _error(code, status):
    return ClientError({"Error": {"Code": code, "Message": "x"}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Op")


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_throttle_pauses_only_that_endpoint_until_the_cooldown_passes():
    clock = Clock()
    limiter = pool.AdaptiveLimiter(initial=4, maximum=8, cooldown=1.5, clock=clock)
    with pytest.raises(ClientError):
        with limiter.slot("lambda"):
            raise _error("TooManyRequestsException", 429)
    assert limiter._paused["lambda"] == 101.5 and limiter._state["lambda"][0] == 2.0
    with limiter.slot("iam"):  # another endpoint is not paused
        pass
    entered = threading.Event()

    def later():
        with limiter.slot("lambda"):
            entered.set()
    worker = threading.Thread(target=later)
    worker.start()
    assert not entered.wait(0.2)  # still inside the cooldown
    clock.now = 101.6
    with limiter._condition:
        limiter._condition.notify_all()
    assert entered.wait(2)
    worker.join()
    assert limiter.waits == 1


def test_non_throttle_errors_do_not_pause():
    clock = Clock()
    limiter = pool.AdaptiveLimiter(cooldown=5, clock=clock)
    with pytest.raises(ClientError):
        with limiter.slot("k"):
            raise _error("AccessDenied", 403)
    assert "k" not in limiter._paused
    with limiter.slot("k"):
        pass
    assert limiter.waits == 0 and limiter.throttles == 0

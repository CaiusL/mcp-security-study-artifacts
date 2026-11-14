"""HostedModel transient-failure retry (model-free).

The hosted client retries a timeout or dropped connection a few times before
raising ModelError, so one slow or dropped Stage 2 request does not end a run.
urllib is patched, so no network call is made.
"""

import json
import unittest

import wiggle.agent_loop as agent_loop
from wiggle.agent_loop import HostedModel, ModelError


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


class HostedModelRetryTests(unittest.TestCase):
    def setUp(self):
        self._orig = agent_loop.urllib.request.urlopen

    def tearDown(self):
        agent_loop.urllib.request.urlopen = self._orig

    def test_retries_transient_timeout_then_succeeds(self):
        calls = {"n": 0}
        payload = {"choices": [{"message": {"content": "ok"}}]}

        def fake(request, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise TimeoutError("read timed out")
            return _Resp(payload)

        agent_loop.urllib.request.urlopen = fake
        model = HostedModel("http://x.test", "k", "m", 0.0, attempts=3, backoff=0)
        turn = model.complete([{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls["n"], 3)
        self.assertEqual(turn.text, "ok")

    def test_raises_after_exhausting_attempts(self):
        calls = {"n": 0}

        def fake(request, timeout=None):
            calls["n"] += 1
            raise TimeoutError("read timed out")

        agent_loop.urllib.request.urlopen = fake
        model = HostedModel("http://x.test", "k", "m", 0.0, attempts=3, backoff=0)
        with self.assertRaises(ModelError):
            model.complete([{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls["n"], 3)


if __name__ == "__main__":
    unittest.main()

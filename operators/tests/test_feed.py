#!/usr/bin/env python3
"""Unit + end-to-end tests for feed.py.

feed.py has no copy of its own in this tree. The manifest comment above
`config.extraFiles."feed.py"` in controllers.yaml claims the test suite
extracts the script from that YAML rather than keeping a separate copy, so
the tests can never drift from what is actually deployed -- this module is
what makes that claim true. It:

  1. Locates controllers.yaml relative to this file (../controllers.yaml,
     since this file is committed at operators/tests/test_feed.py and the
     manifest lives at operators/controllers.yaml), falling back to the
     FEED_MANIFEST env var for other working locations (e.g. running this
     file directly out of /tmp/feed during development).
  2. Pulls the HelmRelease document whose metadata.name == "fluent-bit" and
     reads .spec.values.config.extraFiles."feed.py" out of it -- using
     PyYAML if it's importable, otherwise shelling out to `yq` (present at
     /usr/bin/yq in the environments this runs in) so the suite doesn't hard
     depend on a third-party package being installed.
  3. Compiles and execs that source into a module object registered in
     sys.modules under the name "feed", so every `feed.<attr>` reference
     below -- including tests that mutate feed._state or monkeypatch
     feed._now -- works exactly as it would against a real imported module.

Run it:
    python3 -m unittest test_feed -v

The end-to-end cases start a real server on an ephemeral port and read back
what lands on stdout, because stdout formatting/flushing is the actual
product here and is exactly the part a pure-function test misses.
"""

import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

MANIFEST_DOC_NAME = "fluent-bit"
MANIFEST_YAML_PATH = '.spec.values.config.extraFiles."feed.py"'


def _find_manifest_path():
    """Locate controllers.yaml: relative to this file first, else $FEED_MANIFEST.

    Committed location is operators/tests/test_feed.py, so the manifest is
    ../controllers.yaml from here. Falling back to FEED_MANIFEST lets the
    same file run from other locations (e.g. /tmp/feed during development)
    without silently succeeding against nothing -- if neither resolves we
    raise rather than skip, since a silently-skipped extraction would defeat
    the entire point of this test file.
    """
    relative = Path(__file__).resolve().parent.parent / "controllers.yaml"
    if relative.is_file():
        return relative

    env_path = os.environ.get("FEED_MANIFEST")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate
        raise FileNotFoundError(
            f"FEED_MANIFEST={env_path!r} does not point at a file. "
            "Set it to the path of controllers.yaml."
        )

    raise FileNotFoundError(
        f"Could not locate controllers.yaml at {relative} and the FEED_MANIFEST "
        "environment variable is not set. This test extracts feed.py from the "
        "deployed manifest rather than keeping its own copy, so it cannot run "
        "without a real manifest path -- point FEED_MANIFEST at "
        "operators/controllers.yaml, or run this file from its committed "
        "location (operators/tests/test_feed.py) so the relative path resolves."
    )


def _extract_with_pyyaml(manifest_path):
    import yaml

    with open(manifest_path, "r", encoding="utf-8") as handle:
        documents = list(yaml.safe_load_all(handle))

    for document in documents:
        if isinstance(document, dict) and document.get("metadata", {}).get("name") == MANIFEST_DOC_NAME:
            try:
                return document["spec"]["values"]["config"]["extraFiles"]["feed.py"]
            except (KeyError, TypeError) as exc:
                raise KeyError(
                    f"Found the {MANIFEST_DOC_NAME!r} document in {manifest_path} but "
                    f"{MANIFEST_YAML_PATH} is missing from it. Manifest layout must have "
                    "changed -- update this extractor to match."
                ) from exc

    raise LookupError(
        f"No document with metadata.name == {MANIFEST_DOC_NAME!r} found in {manifest_path}."
    )


def _extract_with_yq(manifest_path):
    query = (
        f'select(.metadata.name == "{MANIFEST_DOC_NAME}") | {MANIFEST_YAML_PATH}'
    )
    result = subprocess.run(
        ["yq", "eval-all", query, str(manifest_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"yq failed extracting {MANIFEST_YAML_PATH} from {manifest_path}: {result.stderr}"
        )
    source = result.stdout
    if not source.strip() or source.strip() == "null":
        raise LookupError(
            f"yq returned nothing for {MANIFEST_YAML_PATH} in the "
            f"{MANIFEST_DOC_NAME!r} document of {manifest_path}. Check the YAML "
            "path and document selector are still correct."
        )
    return source


def _extract_feed_source():
    manifest_path = _find_manifest_path()
    try:
        import yaml  # noqa: F401
    except ImportError:
        return _extract_with_yq(manifest_path)
    else:
        return _extract_with_pyyaml(manifest_path)


def _load_feed_module():
    source = _extract_feed_source()
    spec = importlib.util.spec_from_loader("feed", loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = "<feed.py extracted from controllers.yaml>"
    sys.modules["feed"] = module
    code = compile(source, module.__file__, "exec")
    exec(code, module.__dict__)
    return module, source


feed, FEED_SOURCE = _load_feed_module()


class TestExtraction(unittest.TestCase):
    """Guards the extraction itself, not feed.py's behavior.

    If the YAML path in this file ever drifts from the manifest (a typo in
    MANIFEST_YAML_PATH, a restructure of the HelmRelease), the extractor
    could start returning an empty or unrelated string -- which would make
    every other test in this module vacuously pass against zero real code.
    This makes that failure loud instead of silent.
    """

    def test_extracted_source_is_the_real_script(self):
        self.assertIn("def dedup(", FEED_SOURCE)
        self.assertGreater(len(FEED_SOURCE), 2000)


class DedupStateMixin:
    """Every dedup test needs a clean table -- state is module-global."""

    def setUp(self):
        super().setUp()
        feed._state.clear()
        self._orig_window = feed.WINDOW
        self._orig_max_keys = feed.MAX_KEYS

    def tearDown(self):
        feed.WINDOW = self._orig_window
        feed.MAX_KEYS = self._orig_max_keys
        feed._state.clear()
        super().tearDown()


class TestTruncate(unittest.TestCase):
    def test_under_limit_untouched(self):
        record = {"log": "x" * 599}
        feed.truncate(record)
        self.assertEqual(record["log"], "x" * 599)

    def test_exactly_600_untouched(self):
        record = {"log": "x" * 600}
        feed.truncate(record)
        self.assertEqual(record["log"], "x" * 600)
        self.assertNotIn("truncated", record["log"])

    def test_601_is_truncated(self):
        record = {"log": "x" * 601}
        feed.truncate(record)
        self.assertEqual(record["log"], "x" * 600 + " ...[truncated]")

    def test_message_key_also_truncated(self):
        record = {"message": "y" * 900}
        feed.truncate(record)
        self.assertEqual(record["message"], "y" * 600 + " ...[truncated]")

    def test_non_string_values_untouched(self):
        record = {"log": 12345, "message": None}
        feed.truncate(record)
        self.assertEqual(record["log"], 12345)
        self.assertIsNone(record["message"])

    def test_dict_value_untouched(self):
        payload = {"nested": "z" * 900}
        record = {"log": payload}
        feed.truncate(record)
        self.assertIs(record["log"], payload)

    def test_other_keys_untouched(self):
        record = {"k8s_pod_name": "p" * 900, "reason": "r" * 900}
        feed.truncate(record)
        self.assertEqual(record["k8s_pod_name"], "p" * 900)
        self.assertEqual(record["reason"], "r" * 900)


class TestSignature(unittest.TestCase):
    def test_hex_normalization_collapses_cnpg_session_ids(self):
        """The real-world case that motivated the hex pass.

        CloudNativePG stamps a hex session_id into every record, so two
        otherwise-identical errors a second apart differ only in that token.
        """
        a = feed.signature({"log": "session_id 6a845d2d.4808e", "k8s_pod_name": "gbrain-pg-1"})
        b = feed.signature({"log": "session_id 6a845cf1.4806f", "k8s_pod_name": "gbrain-pg-1"})
        self.assertEqual(a, b)

    def test_both_weaker_rules_would_have_failed(self):
        """Regression guard against the two normalizers that did NOT work.

        Both of these shipped and both leaked the CNPG duplicate into the
        feed. Keeping them here as explicit negatives stops anyone from
        "simplifying" the token rule back into either one.
        """
        one = "session_id 6a845d2d.4808e"
        two = "session_id 6a845cf1.4806f"

        digits_only = re.compile(r"\d+")
        self.assertNotEqual(
            digits_only.sub("#", one),
            digits_only.sub("#", two),
            "digits-only normalization must be insufficient",
        )

        # Hex runs of 6+, then digits. The five-character second component
        # slips past the hex rule and leaves a bare "e" vs "f" behind.
        hex6 = re.compile(r"[0-9A-Fa-f]{6,}")
        self.assertNotEqual(
            digits_only.sub("#", hex6.sub("#", one)),
            digits_only.sub("#", hex6.sub("#", two)),
            "hex-run-of-6 normalization must also be insufficient",
        )

    def test_hex_only_words_without_digits_are_preserved(self):
        """The short-token rule requires a digit, so English survives.

        Over-collapsing would merge two genuinely different errors into one
        signature and silently drop one of them -- the exact failure this
        filter exists to avoid -- so words must not normalize away.
        """
        a = feed.signature({"log": "cafe unreachable", "k8s_pod_name": "pod-a"})
        b = feed.signature({"log": "dead unreachable", "k8s_pod_name": "pod-a"})
        self.assertNotEqual(a, b)

    def test_short_hex_token_with_digit_collapses(self):
        a = feed.signature({"log": "sess 4808e done", "k8s_pod_name": "pod-a"})
        b = feed.signature({"log": "sess 4806f done", "k8s_pod_name": "pod-a"})
        self.assertEqual(a, b)

    def test_long_pure_hex_hash_collapses(self):
        a = feed.signature({"log": "image sha deadbeefcafe", "k8s_pod_name": "pod-a"})
        b = feed.signature({"log": "image sha cafedeadbeef", "k8s_pod_name": "pod-a"})
        self.assertEqual(a, b)

    def test_ordinary_words_are_not_collapsed(self):
        a = feed.signature({"log": "connection refused", "k8s_pod_name": "pod-a"})
        b = feed.signature({"log": "connection timeout", "k8s_pod_name": "pod-a"})
        self.assertNotEqual(a, b)

    def test_different_pods_differ(self):
        a = feed.signature({"log": "identical text", "k8s_pod_name": "pod-a"})
        b = feed.signature({"log": "identical text", "k8s_pod_name": "pod-b"})
        self.assertNotEqual(a, b)

    def test_different_reason_differs(self):
        a = feed.signature({"message": "same", "obj_name": "svc", "reason": "BackOff"})
        b = feed.signature({"message": "same", "obj_name": "svc", "reason": "Unhealthy"})
        self.assertNotEqual(a, b)

    def test_obj_name_used_when_pod_name_absent(self):
        a = feed.signature({"message": "same", "obj_name": "svc-x"})
        b = feed.signature({"message": "same", "obj_name": "svc-y"})
        self.assertNotEqual(a, b)

    def test_only_first_400_chars_considered(self):
        base = "A" * 400
        a = feed.signature({"log": base + "tail-one"})
        b = feed.signature({"log": base + "tail-two"})
        self.assertEqual(a, b)

    def test_falls_through_empty_log_to_message(self):
        via_message = feed.signature({"log": "", "message": "real text"})
        direct = feed.signature({"message": "real text"})
        self.assertEqual(via_message, direct)

    def test_non_string_log_does_not_raise(self):
        self.assertIsInstance(feed.signature({"log": 42}), str)


class TestDedup(DedupStateMixin, unittest.TestCase):
    def _rec(self):
        return {"log": "connection refused", "k8s_pod_name": "pod-a"}

    def test_first_record_emits(self):
        self.assertTrue(feed.dedup(self._rec(), now=1000.0))

    def test_no_suppressed_key_on_first_emit(self):
        record = self._rec()
        feed.dedup(record, now=1000.0)
        self.assertNotIn("suppressed", record)

    def test_identical_record_one_second_later_drops(self):
        feed.dedup(self._rec(), now=1000.0)
        self.assertFalse(feed.dedup(self._rec(), now=1001.0))

    def test_emits_again_after_window_with_suppressed_count(self):
        feed.dedup(self._rec(), now=1000.0)
        for offset in range(1, 6):
            self.assertFalse(feed.dedup(self._rec(), now=1000.0 + offset))
        later = self._rec()
        self.assertTrue(feed.dedup(later, now=1061.0))
        self.assertEqual(later["suppressed"], 5)

    def test_no_suppressed_key_when_nothing_was_suppressed(self):
        feed.dedup(self._rec(), now=1000.0)
        later = self._rec()
        self.assertTrue(feed.dedup(later, now=1061.0))
        self.assertNotIn("suppressed", later)

    def test_window_is_fixed_from_first_emit_not_sliding(self):
        """A steady 1/sec stream must emit at t=0 and again at t=60.

        A sliding window refreshed by each dropped duplicate would emit
        once and then go silent forever, which is the bug this guards.
        """
        emitted_at = []
        for second in range(0, 121):
            if feed.dedup(self._rec(), now=1000.0 + second):
                emitted_at.append(second)
        self.assertEqual(emitted_at, [0, 60, 120])

    def test_distinct_signatures_do_not_interfere(self):
        a = {"log": "err a", "k8s_pod_name": "pod-a"}
        b = {"log": "err b", "k8s_pod_name": "pod-b"}
        self.assertTrue(feed.dedup(a, now=1000.0))
        self.assertTrue(feed.dedup(b, now=1000.0))

    def test_max_keys_overflow_clears_table(self):
        feed.MAX_KEYS = 5
        for i in range(5):
            feed.dedup({"log": f"error {i}", "k8s_pod_name": f"pod-{i}"}, now=1000.0)
        self.assertEqual(len(feed._state), 5)
        # The 6th distinct signature trips the overflow: whole table is
        # dropped, then this one signature is recorded.
        feed.dedup({"log": "error six", "k8s_pod_name": "pod-six"}, now=1000.0)
        self.assertEqual(len(feed._state), 1)

    def test_overflow_never_causes_a_false_drop(self):
        feed.MAX_KEYS = 3
        for i in range(10):
            record = {"log": f"error {i}", "k8s_pod_name": f"pod-{i}"}
            self.assertTrue(feed.dedup(record, now=1000.0))


class TestParseBody(unittest.TestCase):
    def test_json_lines(self):
        body = b'{"log":"a"}\n{"log":"b"}\n'
        self.assertEqual(feed._parse_body(body), [{"log": "a"}, {"log": "b"}])

    def test_json_array(self):
        body = b'[{"log":"a"},{"log":"b"}]'
        self.assertEqual(feed._parse_body(body), [{"log": "a"}, {"log": "b"}])

    def test_blank_lines_ignored(self):
        body = b'{"log":"a"}\n\n\n{"log":"b"}\n'
        self.assertEqual(len(feed._parse_body(body)), 2)

    def test_malformed_line_skipped(self):
        body = b'{"log":"a"}\nNOT JSON AT ALL\n{"log":"b"}\n'
        self.assertEqual(feed._parse_body(body), [{"log": "a"}, {"log": "b"}])

    def test_non_object_entries_skipped(self):
        body = b'{"log":"a"}\n"bare string"\n42\n'
        self.assertEqual(feed._parse_body(body), [{"log": "a"}])

    def test_empty_body(self):
        self.assertEqual(feed._parse_body(b""), [])

    def test_undecodable_body_raises(self):
        with self.assertRaises(UnicodeDecodeError):
            feed._parse_body(b"\xff\xfe\xff")


class TestEndToEnd(DedupStateMixin, unittest.TestCase):
    """Drive a real server over a real socket and read back real stdout."""

    def setUp(self):
        super().setUp()
        self.captured = io.StringIO()
        self._real_stdout = sys.stdout
        sys.stdout = self.captured

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), feed.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        sys.stdout = self._real_stdout
        super().tearDown()

    def _post(self, body, content_type="application/json"):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/",
            data=body if isinstance(body, bytes) else body.encode("utf-8"),
            headers={"Content-Type": content_type},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status

    def _emitted(self):
        raw = self.captured.getvalue()
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def test_json_lines_roundtrip(self):
        body = (
            '{"log":"disk failure","k8s_pod_name":"pod-a"}\n'
            '{"log":"disk failure","k8s_pod_name":"pod-a"}\n'
            '{"log":"other failure","k8s_pod_name":"pod-b"}\n'
        )
        self.assertEqual(self._post(body), 200)
        emitted = self._emitted()
        # The duplicate collapses; the two distinct signatures survive.
        self.assertEqual(len(emitted), 2)
        self.assertEqual(emitted[0]["log"], "disk failure")
        self.assertEqual(emitted[1]["log"], "other failure")

    def test_json_array_body_accepted(self):
        body = json.dumps([{"log": "array form", "k8s_pod_name": "pod-a"}])
        self.assertEqual(self._post(body), 200)
        self.assertEqual(len(self._emitted()), 1)

    def test_malformed_line_does_not_break_batch(self):
        body = (
            '{"log":"good one","k8s_pod_name":"pod-a"}\n'
            "}{ this is not json\n"
            '{"log":"good two","k8s_pod_name":"pod-b"}\n'
        )
        self.assertEqual(self._post(body), 200)
        emitted = self._emitted()
        self.assertEqual([r["log"] for r in emitted], ["good one", "good two"])

    def test_truncation_applied_end_to_end(self):
        body = json.dumps({"log": "E" * 5000, "k8s_pod_name": "pod-a"})
        self.assertEqual(self._post(body), 200)
        emitted = self._emitted()
        self.assertEqual(len(emitted), 1)
        self.assertTrue(emitted[0]["log"].endswith(" ...[truncated]"))
        self.assertEqual(len(emitted[0]["log"]), 600 + len(" ...[truncated]"))

    def test_output_is_one_json_object_per_line(self):
        body = "".join(
            json.dumps({"log": f"distinct error {i}", "k8s_pod_name": f"pod-{i}"}) + "\n"
            for i in range(5)
        )
        self.assertEqual(self._post(body), 200)
        lines = [line for line in self.captured.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 5)
        for line in lines:
            self.assertIsInstance(json.loads(line), dict)

    def test_empty_body_accepted(self):
        self.assertEqual(self._post(b""), 200)
        self.assertEqual(self._emitted(), [])

    def test_non_utf8_body_is_400(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post(b"\xff\xfe\xff")
        self.assertEqual(caught.exception.code, 400)

    def test_unicode_survives_roundtrip(self):
        body = json.dumps({"log": "café ☕ error", "k8s_pod_name": "pod-a"})
        self.assertEqual(self._post(body), 200)
        self.assertEqual(self._emitted()[0]["log"], "café ☕ error")


if __name__ == "__main__":
    unittest.main()

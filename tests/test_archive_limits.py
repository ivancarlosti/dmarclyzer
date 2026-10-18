"""Regression tests for the archive/attachment size limits in ``fetcher.py``.

Only the standard library is required, so the suite runs before the third-party
dependencies are installed.
"""

import gzip
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"
    ),
)

from fetcher import _extract_from_gzip, _extract_from_zip  # noqa: E402
from security import OversizedPayloadError  # noqa: E402

XML = b"<feedback><report_metadata/></feedback>"


def _limits(**overrides):
    limits = {"attachment": 1024, "xml": 1024, "archive": 4096, "entries": 10}
    limits.update(overrides)
    return limits


def _zip_bytes(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


class ZipLimitTests(unittest.TestCase):
    def test_extracts_xml_members_only(self):
        payload = _zip_bytes([("report.xml", XML), ("readme.txt", b"ignored")])
        self.assertEqual(_extract_from_zip(payload, _limits()), [XML.decode()])

    def test_rejects_too_many_entries(self):
        payload = _zip_bytes([(f"report{i}.xml", XML) for i in range(3)])
        with self.assertRaises(OversizedPayloadError):
            _extract_from_zip(payload, _limits(entries=2))

    def test_rejects_oversized_member(self):
        payload = _zip_bytes([("big.xml", b"<a>" + b"x" * 5000 + b"</a>")])
        with self.assertRaises(OversizedPayloadError):
            _extract_from_zip(payload, _limits(xml=1024))

    def test_rejects_total_uncompressed_budget(self):
        payload = _zip_bytes([("a.xml", b"x" * 400), ("b.xml", b"y" * 400)])
        with self.assertRaises(OversizedPayloadError):
            _extract_from_zip(payload, _limits(xml=1000, archive=500))

    def test_compression_bomb_rejected_before_full_read(self):
        # 5 MiB of zeros compresses to a few KiB: a naive read() would inflate
        # the whole member into memory before any size check could run.
        payload = _zip_bytes([("bomb.xml", b"\0" * (5 * 1024 * 1024))])
        self.assertLess(len(payload), 200 * 1024)
        with self.assertRaises(OversizedPayloadError):
            _extract_from_zip(payload, _limits(xml=64 * 1024))


class GzipLimitTests(unittest.TestCase):
    def test_extracts_xml(self):
        payload = gzip.compress(XML)
        self.assertEqual(_extract_from_gzip(payload, _limits()), [XML.decode()])

    def test_rejects_bomb(self):
        payload = gzip.compress(b"\0" * (2 * 1024 * 1024))
        with self.assertRaises(OversizedPayloadError):
            _extract_from_gzip(payload, _limits(xml=32 * 1024))


if __name__ == "__main__":
    unittest.main()

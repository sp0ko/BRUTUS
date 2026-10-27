import datetime
import gzip
import io
import os
import tempfile
import unittest

from utils.geo import GeoLocator, download_db


class _Resp:
    def __init__(self, payload=None, fail=False):
        self.raw = io.BytesIO(gzip.compress(payload or b""))
        self._fail = fail

    def raise_for_status(self):
        if self._fail:
            raise IOError("404")


class TestDownload(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.dest = os.path.join(self.dir.name, "data", "geoip.mmdb")

    def test_downloads_and_unzips(self):
        urls = []

        def get(url, **kw):
            urls.append(url)
            return _Resp(b"MMDB")
        url = download_db(self.dest, get=get, today=datetime.date(2026, 10, 27))
        self.assertIn("2026-10", url)
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"MMDB")
        self.assertEqual(os.listdir(os.path.dirname(self.dest)), ["geoip.mmdb"])

    def test_falls_back_to_previous_month(self):
        def get(url, **kw):
            return _Resp(fail="2026-10" in url, payload=b"X")
        url = download_db(self.dest, get=get, today=datetime.date(2026, 10, 2))
        self.assertIn("2026-09", url)

    def test_failure_leaves_no_file(self):
        with self.assertRaises(RuntimeError):
            download_db(self.dest, get=lambda url, **kw: _Resp(fail=True),
                        today=datetime.date(2026, 10, 2))
        self.assertFalse(os.path.exists(self.dest))


class TestOnlineFallback(unittest.TestCase):
    def test_fallback_disabled_never_goes_online(self):
        geo = GeoLocator(online_fallback=False)
        geo._reader = None
        geo._lookup_online = lambda ip: self.fail("online lookup attempted")
        self.assertIsNone(geo.lookup("8.8.8.8"))

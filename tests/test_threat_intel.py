import unittest

from utils.threat_intel import DEFAULT_SOURCES, _parse_feed


class TestFeodoTrackerSource(unittest.TestCase):

    def test_feodo_tracker_is_a_default_source(self):
        self.assertEqual(
            DEFAULT_SOURCES["feodo_tracker"],
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        )

    def test_plain_text_ip_entries_are_parsed(self):
        feed = "# Feodo Tracker IP blocklist\n1.2.3.4\n198.51.100.0/24\n"
        self.assertEqual(_parse_feed(feed), ["1.2.3.4", "198.51.100.0/24"])


if __name__ == "__main__":
    unittest.main()

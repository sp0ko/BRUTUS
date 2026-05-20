"""
Testy jednostkowe dla BruteForceTracker.

Uruchomienie:
    python -m pytest tests/ -v
    # lub bez pytest:
    python -m unittest tests/test_tracker.py -v
"""

import time
import unittest

from detector.tracker import BruteForceTracker, AlertEvent


class TestBruteForceTracker(unittest.TestCase):

    def _make_tracker(self, threshold=5, time_window=60, cooldown=0):
        return BruteForceTracker(
            threshold=threshold,
            time_window=time_window,
            alert_cooldown=cooldown,
            success_failure_threshold=3,
        )

    # ------------------------------------------------------------------
    # Podstawowe: wyzwalanie alertu
    # ------------------------------------------------------------------

    def test_alert_triggered_at_threshold(self):
        tracker = self._make_tracker(threshold=5)
        alert = None
        for i in range(5):
            alert = tracker.record_failed(ip="1.2.3.4", username="root")
        self.assertIsNotNone(alert, "Alert powinien zostać wygenerowany po osiągnięciu progu")
        self.assertIsInstance(alert, AlertEvent)

    def test_no_alert_below_threshold(self):
        tracker = self._make_tracker(threshold=5)
        for i in range(4):
            alert = tracker.record_failed(ip="1.2.3.4", username="root")
            self.assertIsNone(alert, f"Po {i+1} próbach nie powinno być alertu")

    def test_alert_contains_correct_ip(self):
        tracker = self._make_tracker(threshold=3)
        for _ in range(3):
            alert = tracker.record_failed(ip="10.20.30.40", username="admin")
        self.assertEqual(alert.ip, "10.20.30.40")

    def test_alert_contains_correct_count(self):
        tracker = self._make_tracker(threshold=3)
        for _ in range(5):
            alert = tracker.record_failed(ip="1.2.3.4")
        self.assertGreaterEqual(alert.count, 3)

    def test_alert_collects_multiple_usernames(self):
        tracker = self._make_tracker(threshold=3)
        users = ["root", "admin", "ubuntu"]
        for u in users:
            tracker.record_failed(ip="1.2.3.4", username=u)
        alert = tracker.record_failed(ip="1.2.3.4", username="deploy")
        self.assertIsNotNone(alert)
        for u in users:
            self.assertIn(u, alert.usernames)

    # ------------------------------------------------------------------
    # Sliding window: eviction
    # ------------------------------------------------------------------

    def test_old_events_evicted_from_window(self):
        """Próby starsze niż time_window nie wliczają się do licznika."""
        tracker = self._make_tracker(threshold=3, time_window=2)
        old_ts = time.time() - 10   # 10 sekund temu — poza oknem 2s

        for _ in range(3):
            alert = tracker.record_failed(ip="5.5.5.5", timestamp=old_ts)

        self.assertIsNone(alert, "Stare zdarzenia nie powinny triggerować alertu")

    def test_fresh_events_within_window_trigger(self):
        tracker = self._make_tracker(threshold=3, time_window=60)
        for _ in range(3):
            alert = tracker.record_failed(ip="5.5.5.5")
        self.assertIsNotNone(alert)

    # ------------------------------------------------------------------
    # Cooldown alertów
    # ------------------------------------------------------------------

    def test_cooldown_suppresses_repeated_alert(self):
        """Ten sam IP nie wyzwala drugiego alertu w trakcie cooldown."""
        tracker = self._make_tracker(threshold=3, cooldown=300)
        for _ in range(3):
            tracker.record_failed(ip="9.9.9.9")
        # Drugi zestaw prób — cooldown aktywny
        second_alert = None
        for _ in range(3):
            second_alert = tracker.record_failed(ip="9.9.9.9")
        self.assertIsNone(second_alert, "Cooldown powinien wyciszyć drugi alert")

    def test_zero_cooldown_allows_repeated_alerts(self):
        """cooldown=0 pozwala na alert przy każdym przekroczeniu progu."""
        tracker = self._make_tracker(threshold=3, cooldown=0)
        alerts = []
        for i in range(6):
            a = tracker.record_failed(ip="7.7.7.7")
            if a:
                alerts.append(a)
        self.assertGreaterEqual(len(alerts), 2)

    # ------------------------------------------------------------------
    # Izolacja IP
    # ------------------------------------------------------------------

    def test_different_ips_tracked_independently(self):
        tracker = self._make_tracker(threshold=5)
        for _ in range(3):
            tracker.record_failed(ip="1.1.1.1")
        for _ in range(3):
            tracker.record_failed(ip="2.2.2.2")
        # Oba IPs poniżej progu 5 — brak alertu
        self.assertIsNone(tracker.record_failed(ip="1.1.1.1"))  # 4. próba
        # 5. próba z 1.1.1.1 — alert
        alert = tracker.record_failed(ip="1.1.1.1")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.ip, "1.1.1.1")
        # 2.2.2.2 ma tylko 3 próby — bez alertu
        self.assertIsNone(tracker.record_failed(ip="2.2.2.2"))  # 4. próba

    # ------------------------------------------------------------------
    # Udane logowanie po ataku
    # ------------------------------------------------------------------

    def test_success_after_failures_returns_critical_event(self):
        tracker = self._make_tracker(threshold=5, cooldown=0)
        for _ in range(4):
            tracker.record_failed(ip="3.3.3.3", username="root")
        alert = tracker.record_success(ip="3.3.3.3", username="root")
        self.assertIsNotNone(alert, "Udane logowanie po próbach powinno generować alert krytyczny")
        self.assertTrue(alert.successful_login)

    def test_success_without_prior_failures_no_alert(self):
        tracker = self._make_tracker(threshold=5)
        alert = tracker.record_success(ip="8.8.8.8", username="admin")
        self.assertIsNone(alert, "Udane logowanie bez wcześniejszych prób — brak alertu")

    def test_successful_alert_is_critical(self):
        tracker = self._make_tracker(threshold=3, cooldown=0)
        for _ in range(3):
            tracker.record_failed(ip="4.4.4.4")
        alert = tracker.record_success(ip="4.4.4.4", username="root")
        self.assertIsNotNone(alert)
        self.assertTrue(alert.is_critical())

    # ------------------------------------------------------------------
    # Statystyki
    # ------------------------------------------------------------------

    def test_get_stats_returns_active_ips(self):
        tracker = self._make_tracker(threshold=10)
        tracker.record_failed(ip="11.11.11.11")
        tracker.record_failed(ip="22.22.22.22")
        stats = tracker.get_stats()
        self.assertIn("11.11.11.11", stats)
        self.assertIn("22.22.22.22", stats)

    def test_reset_ip_clears_tracking(self):
        tracker = self._make_tracker(threshold=10)
        for _ in range(5):
            tracker.record_failed(ip="55.55.55.55")
        tracker.reset_ip("55.55.55.55")
        stats = tracker.get_stats()
        self.assertNotIn("55.55.55.55", stats)

    # ------------------------------------------------------------------
    # Attack type
    # ------------------------------------------------------------------

    def test_attack_type_recorded(self):
        tracker = self._make_tracker(threshold=3, cooldown=0)
        for _ in range(3):
            tracker.record_failed(ip="6.6.6.6", attack_type="RDP")
        alert = tracker.record_failed(ip="6.6.6.6", attack_type="RDP")
        self.assertIsNotNone(alert)
        self.assertIn("RDP", alert.attack_type)


if __name__ == "__main__":
    unittest.main(verbosity=2)

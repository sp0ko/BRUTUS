import unittest
from datetime import datetime, timezone

from detector.parsers import PARSER_REGISTRY, get_parser
from detector.parsers.ftp import FtpParser
from detector.parsers.http_auth import ApacheParser, NginxParser
from detector.parsers.mysql import MySQLParser


def access(status, method="GET", path="/", user="-", ip="203.0.113.9"):
    return (f'{ip} - {user} [26/Oct/2026:13:00:00 +0000] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "curl/8"')


class TestHttpAuth(unittest.TestCase):
    def setUp(self):
        self.p = NginxParser()

    def test_basic_auth_failure_with_user(self):
        ev = self.p.parse_line(access(401, user="admin", path="/secret"))
        self.assertEqual((ev.event_type, ev.ip, ev.username, ev.attack_type),
                         ("FAILED", "203.0.113.9", "admin", "HTTP"))

    def test_browser_challenge_ignored(self):
        self.assertIsNone(self.p.parse_line(access(401)))

    def test_normal_traffic_ignored(self):
        self.assertIsNone(self.p.parse_line(access(200)))
        self.assertIsNone(self.p.parse_line(access(404, path="/x")))
        self.assertIsNone(self.p.parse_line(access(200, "POST", "/login")))

    def test_wordpress_login(self):
        self.assertEqual(self.p.parse_line(access(200, "POST", "/wp-login.php")).event_type, "FAILED")
        self.assertEqual(self.p.parse_line(access(302, "POST", "/wp-login.php")).event_type, "SUCCESS")
        self.assertIsNone(self.p.parse_line(access(200, "GET", "/wp-login.php")))

    def test_generic_login_panel(self):
        self.assertEqual(self.p.parse_line(access(401, "POST", "/login")).event_type, "FAILED")
        self.assertEqual(self.p.parse_line(access(403, "POST", "/administrator/")).event_type, "FAILED")
        self.assertIsNone(self.p.parse_line(access(403, "POST", "/blog/post")))

    def test_ipv6(self):
        ev = self.p.parse_line(access(401, user="bob", ip="2001:db8::1"))
        self.assertEqual(ev.ip, "2001:db8::1")

    def test_timestamp(self):
        ev = self.p.parse_line(access(401, user="bob"))
        self.assertEqual(ev.timestamp, datetime(2026, 10, 26, 13, 0, tzinfo=timezone.utc).timestamp())

    def test_nginx_error_log(self):
        line = ('2026/10/26 13:00:00 [error] 1#1: *5 user "bob": password mismatch, '
                'client: 198.51.100.4, server: x, request: "GET / HTTP/1.1"')
        ev = self.p.parse_line(line)
        self.assertEqual((ev.ip, ev.username), ("198.51.100.4", "bob"))
        line = ('2026/10/26 13:00:00 [error] 1#1: *5 user "eve" was not found in "/etc/nginx/.htpasswd", '
                'client: 198.51.100.4, server: x')
        self.assertEqual(self.p.parse_line(line).username, "eve")

    def test_apache_error_log(self):
        line = ('[Mon Oct 26 13:00:00.123456 2026] [auth_basic:error] [pid 1] '
                '[client 198.51.100.4:5555] AH01617: user bob: authentication failure for "/": Password Mismatch')
        ev = ApacheParser().parse_line(line)
        self.assertEqual((ev.event_type, ev.ip, ev.username), ("FAILED", "198.51.100.4", "bob"))
        line = ('[Mon Oct 26 13:00:00.1 2026] [auth_basic:error] [pid 1] '
                '[client 198.51.100.4:5555] AH01618: user eve not found: /')
        self.assertEqual(ApacheParser().parse_line(line).username, "eve")

    def test_garbage(self):
        self.assertIsNone(self.p.parse_line(""))
        self.assertIsNone(self.p.parse_line("totally unrelated line"))


class TestFtp(unittest.TestCase):
    def setUp(self):
        self.p = FtpParser()

    def test_vsftpd(self):
        ev = self.p.parse_line('Mon Oct 26 13:00:00 2026 [pid 12] [bob] FAIL LOGIN: Client "198.51.100.7"')
        self.assertEqual((ev.event_type, ev.ip, ev.username, ev.attack_type),
                         ("FAILED", "198.51.100.7", "bob", "FTP"))
        ok = self.p.parse_line('Mon Oct 26 13:00:00 2026 [pid 12] [bob] OK LOGIN: Client "::ffff:198.51.100.7"')
        self.assertEqual((ok.event_type, ok.ip), ("SUCCESS", "198.51.100.7"))

    def test_proftpd(self):
        ev = self.p.parse_line("Oct 26 13:00:00 h proftpd[1]: h (198.51.100.7[198.51.100.7]) - "
                               "USER bob (Login failed): Incorrect password")
        self.assertEqual((ev.event_type, ev.ip, ev.username), ("FAILED", "198.51.100.7", "bob"))
        ev = self.p.parse_line("Oct 26 13:00:00 h proftpd[1]: h (198.51.100.7[198.51.100.7]) - "
                               "USER bob: Login successful.")
        self.assertEqual(ev.event_type, "SUCCESS")
        ev = self.p.parse_line("Oct 26 13:00:00 h proftpd[1]: h (198.51.100.7[198.51.100.7]) - "
                               "USER eve: no such user found from 198.51.100.7 [198.51.100.7] to 10.0.0.1:21")
        self.assertEqual((ev.event_type, ev.username), ("FAILED", "eve"))

    def test_pureftpd(self):
        ev = self.p.parse_line("Oct 26 13:00:00 h pure-ftpd: (?@198.51.100.7) [WARNING] "
                               "Authentication failed for user [bob]")
        self.assertEqual((ev.event_type, ev.ip, ev.username), ("FAILED", "198.51.100.7", "bob"))
        ev = self.p.parse_line("Oct 26 13:00:00 h pure-ftpd: (bob@198.51.100.7) [INFO] bob is now logged in")
        self.assertEqual((ev.event_type, ev.ip, ev.username), ("SUCCESS", "198.51.100.7", "bob"))

    def test_garbage(self):
        self.assertIsNone(self.p.parse_line("Oct 26 13:00:00 h sshd[1]: hello"))


class TestMySQL(unittest.TestCase):
    def setUp(self):
        self.p = MySQLParser()

    def test_mysql8(self):
        ev = self.p.parse_line("2026-10-26T13:00:00.123456Z 12 [Note] [MY-010926] [Server] "
                               "Access denied for user 'root'@'198.51.100.7' (using password: YES)")
        self.assertEqual((ev.event_type, ev.ip, ev.username, ev.attack_type),
                         ("FAILED", "198.51.100.7", "root", "MYSQL"))
        self.assertEqual(ev.timestamp, datetime(2026, 10, 26, 13, 0, tzinfo=timezone.utc).timestamp())

    def test_mariadb_syslog_and_mapped_ipv6(self):
        ev = self.p.parse_line("Oct 26 13:00:00 h mariadbd[1]: 2026-10-26 13:00:00 5 [Warning] "
                               "Access denied for user 'sa'@'::ffff:198.51.100.7' (using password: NO)")
        self.assertEqual(ev.ip, "198.51.100.7")

    def test_hostname_and_noise_ignored(self):
        self.assertIsNone(self.p.parse_line("Access denied for user 'root'@'evil.example.com'"))
        self.assertIsNone(self.p.parse_line("2026-10-26T13:00:00Z 1 [Note] ready for connections"))


class TestRegistry(unittest.TestCase):
    def test_registered(self):
        for name in ("nginx", "apache", "ftp", "mysql"):
            self.assertIn(name, PARSER_REGISTRY)
            self.assertEqual(get_parser(name).name, name)


class TestEndToEnd(unittest.TestCase):
    """Parser → tracker pipeline via replay, as `--replay FILE --type X` does it."""

    def _replay(self, parser, lines):
        import os
        import tempfile
        from detector.replay import replay_file
        from detector.tracker import BruteForceTracker
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "svc.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            return replay_file(path, parser, BruteForceTracker(threshold=5, time_window=60, alert_cooldown=0))

    def test_nginx_wp_login_burst(self):
        lines = [access(200, "POST", "/wp-login.php").replace("13:00:00", f"13:00:{s:02d}") for s in range(6)]
        res = self._replay("nginx", lines)
        self.assertEqual(res.alerts[0].attack_type, "HTTP")

    def test_ftp_burst(self):
        lines = [f'Mon Oct 26 13:00:{s:02d} 2026 [pid 1] [u{s}] FAIL LOGIN: Client "198.51.100.7"' for s in range(6)]
        self.assertEqual(self._replay("ftp", lines).alerts[0].attack_type, "FTP")

    def test_mysql_burst(self):
        lines = [f"2026-10-26T13:00:{s:02d}.000000Z 1 [Note] [MY-010926] [Server] "
                 "Access denied for user 'root'@'198.51.100.7' (using password: YES)" for s in range(6)]
        self.assertEqual(self._replay("mysql", lines).alerts[0].attack_type, "MYSQL")


if __name__ == "__main__":
    unittest.main()

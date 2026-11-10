"""
Phase 1 tests. Run from the project root with:
    python -m unittest discover -s tests -v
No web framework is needed for these tests.
"""
import os
import random
import socket
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from connectors import ConnectorError, FileUploadConnector, RestApiConnector, build_connector  # noqa: E402
from connectors.models import Incident, normalize_severity  # noqa: E402
from connectors.rest_api import to_common_format  # noqa: E402
from source_app.data import SAMPLE_INCIDENTS, IncidentStore  # noqa: E402
from tests.fake_server import API_KEY, FakeServer  # noqa: E402

KB_PATH = os.path.join(ROOT, "sample_data", "KnowledgeBase.txt")


class CommonFormatTests(unittest.TestCase):
    def test_severity_normalisation(self):
        self.assertEqual(normalize_severity("CRITICAL"), "Critical")
        self.assertEqual(normalize_severity("high - lateral movement"), "High")
        self.assertEqual(normalize_severity("moderate"), "Medium")
        self.assertEqual(normalize_severity(""), "Unknown")
        self.assertEqual(normalize_severity(None), "Unknown")

    def test_round_trip(self):
        original = to_common_format(SAMPLE_INCIDENTS[0], "Test")
        restored = Incident.from_dict(original.to_dict())
        self.assertEqual(original, restored)


class SourceAppTests(unittest.TestCase):
    def test_sample_incidents_convert_cleanly(self):
        for native in SAMPLE_INCIDENTS:
            incident = to_common_format(native, "Test")
            self.assertTrue(incident.id and incident.title and incident.summary)
            self.assertIn(incident.severity, {"Low", "Medium", "High", "Critical"})
            self.assertTrue(incident.host.hostname)
            self.assertTrue(incident.techniques)
            self.assertTrue(incident.timeline)

    def test_sample_hashes_are_well_formed(self):
        for native in SAMPLE_INCIDENTS:
            for item in native["indicators"]:
                if item["type"] == "hash":
                    self.assertEqual(len(item["value"]), 64)

    def test_simulate_adds_unique_incidents(self):
        store = IncidentStore()
        before = len(store.list_summaries())
        first = store.simulate_new(random.Random(1))
        second = store.simulate_new(random.Random(2))
        self.assertEqual(len(store.list_summaries()), before + 2)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["state"], "open")
        to_common_format(first, "Test")   # simulated data must convert too

    def test_actions(self):
        store = IncidentStore()
        record = store.record_action("INC-2026-0003", "isolate_host", "FILESRV-01")
        self.assertEqual(record["status"], "executed")
        self.assertEqual(store.get("INC-2026-0003")["state"], "contained")
        with self.assertRaises(ValueError):
            store.record_action("INC-2026-0003", "delete_everything", "x")
        with self.assertRaises(ValueError):
            store.record_action("INC-2026-0003", "block_ip", "  ")
        with self.assertRaises(KeyError):
            store.record_action("INC-9999-0000", "block_ip", "1.2.3.4")


class FileConnectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(KB_PATH, encoding="utf-8") as handle:
            cls.text = handle.read()
        cls.incident = FileUploadConnector("KB", "KnowledgeBase.txt", cls.text).fetch_incidents()[0]

    def test_header_fields(self):
        inc = self.incident
        self.assertEqual(inc.id, "INC-2026-0001")
        self.assertEqual(inc.severity, "Critical")
        self.assertEqual(inc.created_at, "2026-08-07")
        self.assertEqual(inc.threat_actor, "APT29")

    def test_host_and_network(self):
        inc = self.incident
        self.assertEqual(inc.host.hostname, "FINANCE-PC-07")
        self.assertEqual(inc.host.username, "john.smith")
        self.assertEqual(inc.host.ip, "192.168.10.25")
        self.assertEqual(inc.network.destination_ips, ["185.244.25.17", "45.91.203.56"])
        self.assertEqual(inc.network.port, "443")
        self.assertEqual(inc.network.bytes_out, "1.8 GB")

    def test_indicators(self):
        ind = self.incident.indicators
        self.assertIn("185.244.25.17", ind.ips)
        self.assertEqual(ind.domains, ["secure-update-check.com", "cdn-security-sync.net"])
        self.assertEqual(len(ind.hashes), 3)
        self.assertEqual(ind.cves, ["CVE-2023-23397", "CVE-2021-34527"])
        self.assertEqual(ind.emails, ["support@company-security-alert.com"])

    def test_techniques_and_timeline(self):
        inc = self.incident
        self.assertEqual([t.id for t in inc.techniques],
                         ["T1566", "T1059.001", "T1003", "T1041", "T1547", "T1071.001"])
        self.assertEqual(inc.techniques[1].name, "PowerShell")
        times = [e.time for e in inc.timeline]
        self.assertEqual(times[0], "08:40")
        self.assertEqual(times[-1], "09:20")
        self.assertEqual(len(inc.timeline), 18)

    def test_summary_is_clean(self):
        self.assertTrue(self.incident.summary.startswith("On 07 August 2026"))
        self.assertNotIn("Overall Severity", self.incident.summary)

    def test_empty_file(self):
        connector = FileUploadConnector("x", "x.txt", "   ")
        self.assertFalse(connector.test_connection()[0])
        with self.assertRaises(ConnectorError):
            connector.fetch_incidents()

    def test_unstructured_text_still_works(self):
        text = "Failed logins from 203.0.113.9 at 02:11 then success. Severity: High"
        incident = FileUploadConnector("x", "notes.txt", text).fetch_incidents()[0]
        self.assertEqual(incident.severity, "High")
        self.assertEqual(incident.indicators.ips, ["203.0.113.9"])
        self.assertTrue(incident.id.startswith("FILE-"))


class RestConnectorTests(unittest.TestCase):
    def test_good_connection_and_fetch(self):
        with FakeServer() as server:
            connector = RestApiConnector("Demo", server.url, API_KEY)
            ok, message = connector.test_connection()
            self.assertTrue(ok, message)
            self.assertIn("4 incident", message)
            incidents = connector.fetch_incidents()
        self.assertEqual([i.id for i in incidents],
                         [n["id"] for n in SAMPLE_INCIDENTS])
        first = incidents[0]
        self.assertEqual(first.source, "Demo")
        self.assertEqual(first.severity, "Critical")
        self.assertEqual(first.host.hostname, "FINANCE-PC-07")
        self.assertEqual(first.network.port, "443")

    def test_new_incident_appears_on_next_sync(self):
        with FakeServer() as server:
            connector = RestApiConnector("Demo", server.url, API_KEY)
            self.assertEqual(len(connector.fetch_incidents()), 4)
            server.store.simulate_new(random.Random(5))
            self.assertEqual(len(connector.fetch_incidents()), 5)

    def test_wrong_key(self):
        with FakeServer() as server:
            ok, message = RestApiConnector("Demo", server.url, "nope").test_connection()
        self.assertFalse(ok)
        self.assertIn("API key", message)

    def test_server_not_running(self):
        # Find a local port with nothing listening on it. Windows waits and times out
        # instead of refusing at once, so either wording is a correct, readable error.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        ok, message = RestApiConnector("Demo", f"http://127.0.0.1:{port}", API_KEY, timeout=2).test_connection()
        self.assertFalse(ok)
        self.assertTrue("Could not reach" in message or "did not answer" in message, message)

    def test_url_without_scheme_and_trailing_slash(self):
        with FakeServer() as server:
            bare = server.url.replace("http://", "") + "/"
            self.assertTrue(RestApiConnector("Demo", bare, API_KEY).test_connection()[0])

    def test_fetch_raises_readable_error(self):
        with FakeServer() as server:
            connector = RestApiConnector("Demo", server.url, "nope")
            with self.assertRaises(ConnectorError):
                connector.fetch_incidents()


class FactoryTests(unittest.TestCase):
    def test_build_connector(self):
        rest = build_connector({"type": "rest", "name": "a", "base_url": "http://x", "api_key": "k"})
        self.assertIsInstance(rest, RestApiConnector)
        file_ = build_connector({"type": "file", "name": "b", "filename": "f.txt", "text": "hi"})
        self.assertIsInstance(file_, FileUploadConnector)
        with self.assertRaises(ConnectorError):
            build_connector({"type": "ftp"})


if __name__ == "__main__":
    unittest.main()

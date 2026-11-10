"""
Phase 4 tests: action proposals (and the checks that stop made-up targets),
sending approved actions to the platform, and the audit log.
Run from the project root:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cryptography.fernet import Fernet  # noqa: E402

import ai_actions as aa  # noqa: E402
import database as database_module  # noqa: E402
from ai_analysis import AIError  # noqa: E402
from connectors import ConnectorError, FileUploadConnector, RestApiConnector  # noqa: E402
from connectors.rest_api import to_common_format  # noqa: E402
from database import Database  # noqa: E402
from security import SecretBox, hash_password  # noqa: E402
from source_app.data import SAMPLE_INCIDENTS  # noqa: E402
from tests.fake_server import API_KEY, FakeServer  # noqa: E402
from tests.test_phase2 import FakeLLM  # noqa: E402


def incident(n):
    return to_common_format(SAMPLE_INCIDENTS[n], "SOC").to_dict()


class AllowedTargetTests(unittest.TestCase):
    def test_phishing_incident(self):
        targets = aa.allowed_targets(incident(0))
        self.assertEqual(targets["block_ip"], ["185.244.25.17", "45.91.203.56"])   # no 192.168.x.x
        self.assertEqual(targets["isolate_host"], ["FINANCE-PC-07"])
        self.assertEqual(targets["disable_account"], ["john.smith"])

    def test_internal_addresses_can_never_be_blocked(self):
        targets = aa.allowed_targets(incident(3))       # insider incident, only internal IPs
        self.assertEqual(targets["block_ip"], [])

    def test_brute_force_source_is_blockable(self):
        self.assertEqual(aa.allowed_targets(incident(1))["block_ip"], ["203.0.113.45"])

    def test_uploaded_report(self):
        with open(os.path.join(ROOT, "sample_data", "KnowledgeBase.txt"), encoding="utf-8") as handle:
            kb = FileUploadConnector("KB", "k.txt", handle.read()).fetch_incidents()[0].to_dict()
        self.assertIn("185.244.25.17", aa.allowed_targets(kb)["block_ip"])
        self.assertNotIn("192.168.10.25", aa.allowed_targets(kb)["block_ip"])


class ParseProposalTests(unittest.TestCase):
    def setUp(self):
        self.inc = incident(0)

    def reply(self, items, wrap=""):
        text = json.dumps(items)
        return {"": text, "fence": f"```json\n{text}\n```", "chatty": f"Sure! Here you go:\n{text}\nHope it helps."}[wrap]

    GOOD = [
        {"action": "isolate_host", "target": "FINANCE-PC-07", "reason": "Confirmed compromise", "priority": "high"},
        {"action": "block_ip", "target": "185.244.25.17", "reason": "C2 address", "priority": "medium"},
        {"action": "disable_account", "target": "john.smith", "reason": "Credentials stolen", "priority": "high"},
    ]

    def test_valid_proposals_in_any_wrapping(self):
        for wrap in ("", "fence", "chatty"):
            proposals, dropped = aa.parse_proposals(self.reply(self.GOOD, wrap), self.inc)
            self.assertEqual(len(proposals), 3, wrap)
            self.assertEqual(dropped, 0)
            self.assertTrue(all(p["status"] == "proposed" for p in proposals))
        # highest priority first
        self.assertEqual(proposals[-1]["priority"], "medium")

    def test_made_up_targets_and_actions_are_dropped(self):
        items = self.GOOD + [
            {"action": "block_ip", "target": "8.8.8.8", "reason": "invented", "priority": "high"},
            {"action": "block_ip", "target": "192.168.10.25", "reason": "internal host", "priority": "high"},
            {"action": "isolate_host", "target": "DOMAIN-CONTROLLER-01", "reason": "invented", "priority": "high"},
            {"action": "wipe_disk", "target": "FINANCE-PC-07", "reason": "not allowed", "priority": "high"},
            "not even an object",
        ]
        proposals, dropped = aa.parse_proposals(json.dumps(items), self.inc)
        self.assertEqual(len(proposals), 3)
        self.assertEqual(dropped, 5)

    def test_case_is_normalised_and_duplicates_removed(self):
        items = [{"action": "ISOLATE_HOST", "target": "finance-pc-07", "reason": "x", "priority": "HIGH"}] * 2
        proposals, _ = aa.parse_proposals(json.dumps(items), self.inc)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["target"], "FINANCE-PC-07")   # the exact value from the incident

    def test_bad_priority_becomes_medium_and_reason_is_capped(self):
        items = [{"action": "block_ip", "target": "185.244.25.17", "reason": "r" * 900, "priority": "urgent!!"}]
        proposals, _ = aa.parse_proposals(json.dumps(items), self.inc)
        self.assertEqual(proposals[0]["priority"], "medium")
        self.assertLessEqual(len(proposals[0]["reason"]), 300)

    def test_empty_list_is_fine_and_garbage_is_an_error(self):
        self.assertEqual(aa.parse_proposals("[]", self.inc), ([], 0))
        for garbage in ("no json here", "[not valid json", '{"action": "block_ip"}'):
            with self.assertRaises(AIError):
                aa.parse_proposals(garbage, self.inc)

    def test_propose_actions_with_fake_model(self):
        llm = FakeLLM(json.dumps(self.GOOD))
        proposals, dropped = aa.propose_actions(self.inc, llm)
        self.assertEqual((len(proposals), dropped), (3, 0))
        prompt = llm.prompts[0]
        self.assertIn("block_ip (Block IP address): 185.244.25.17, 45.91.203.56", prompt)
        self.assertIn("isolate_host (Isolate host): FINANCE-PC-07", prompt)
        self.assertIn("copy them exactly", prompt)


class RuleBasedTests(unittest.TestCase):
    def test_severe_incident(self):
        proposals = aa.rule_based_proposals(incident(0))
        kinds = sorted((p["action"], p["target"]) for p in proposals)
        self.assertEqual(kinds, [("block_ip", "185.244.25.17"), ("block_ip", "45.91.203.56"),
                                 ("disable_account", "john.smith"), ("isolate_host", "FINANCE-PC-07")])
        self.assertTrue(all(p["source"] == "rules" for p in proposals))

    def test_low_severity_internal_incident_gets_no_isolation(self):
        actions = {p["action"] for p in aa.rule_based_proposals(incident(3))}
        self.assertNotIn("isolate_host", actions)
        self.assertNotIn("block_ip", actions)


class SendActionTests(unittest.TestCase):
    def test_action_reaches_the_platform_and_changes_status(self):
        with FakeServer() as server:
            connector = RestApiConnector("SOC", server.url, API_KEY)
            record = connector.send_action("INC-2026-0003", "isolate_host", "FILESRV-01", requested_by="alice")
            self.assertEqual(record["status"], "executed")
            self.assertEqual(record["requested_by"], "alice")
            after = {i.id: i for i in connector.fetch_incidents()}
            self.assertEqual(after["INC-2026-0003"].status, "Contained")
            self.assertEqual(len(server.store.list_actions()), 1)

    def test_platform_errors_are_readable(self):
        with FakeServer() as server:
            connector = RestApiConnector("SOC", server.url, API_KEY)
            with self.assertRaises(ConnectorError) as bad_action:
                connector.send_action("INC-2026-0003", "format_c_drive", "x")
            self.assertIn("Unsupported action", str(bad_action.exception))
            with self.assertRaises(ConnectorError) as missing:
                connector.send_action("INC-9999-0000", "block_ip", "203.0.113.5")
            self.assertIn("not found", str(missing.exception).lower())
            with self.assertRaises(ConnectorError) as wrong_key:
                RestApiConnector("SOC", server.url, "nope").send_action("INC-2026-0003", "block_ip", "203.0.113.5")
            self.assertIn("API key", str(wrong_key.exception))
            self.assertEqual(server.store.list_actions(), [])


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        original = database_module.hash_password
        database_module.hash_password = lambda p: hash_password(p, iterations=1000)
        self.addCleanup(lambda: setattr(database_module, "hash_password", original))
        self.db = Database(Path(self.tmp.name) / "t.db", SecretBox(Fernet.generate_key()))
        self.alice = self.db.create_user("alice", "correct-horse-battery")
        self.bobby = self.db.create_user("bobby", "another-strong-pw")

    def entry(self, **over):
        base = {"incident_id": "INC-1", "connection_name": "SOC", "action": "block_ip", "target": "203.0.113.5",
                "proposed_by": "ai", "decision": "approved", "result": "executed", "detail": "ok"}
        return {**base, **over}

    def test_log_and_list(self):
        self.db.log_action(self.alice["id"], self.entry())
        self.db.log_action(self.alice["id"], self.entry(decision="rejected", result="none", target="203.0.113.6"))
        self.db.log_action(self.alice["id"], self.entry(incident_id="INC-2"))
        rows = self.db.list_action_log(self.alice["id"], "INC-1")
        self.assertEqual([r["target"] for r in rows], ["203.0.113.6", "203.0.113.5"])   # newest first
        self.assertEqual(rows[0]["decision"], "rejected")
        self.assertEqual(len(self.db.list_action_log(self.alice["id"])), 3)

    def test_users_only_see_their_own_log(self):
        self.db.log_action(self.alice["id"], self.entry())
        self.assertEqual(self.db.list_action_log(self.bobby["id"]), [])

    def test_existing_databases_gain_the_table(self):
        again = Database(Path(self.tmp.name) / "t.db", self.db.secrets)      # re-open the same file
        self.assertEqual(again.list_action_log(self.alice["id"]), [])


if __name__ == "__main__":
    unittest.main()

"""
Phase 2 tests: dashboard numbers, AI analysis (with a fake model) and the PDF report.
Run from the project root:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ai_analysis as ai  # noqa: E402
import dashboard_data as dd  # noqa: E402
from connectors import FileUploadConnector, RestApiConnector  # noqa: E402
from connectors.rest_api import to_common_format  # noqa: E402
from report_pdf import build_pdf_report, inline_markup, pdf_safe  # noqa: E402
from source_app.data import SAMPLE_INCIDENTS  # noqa: E402
from tests.fake_server import API_KEY, FakeServer  # noqa: E402

GOOD_REPLY = """Here is the analysis.

### Incident Summary
A finance workstation was compromised through phishing.

### Attack Type
Phishing followed by data exfiltration

### Severity
Critical - 1.8 GB left the network.

### Root Cause
A disguised executable was opened. MFA was disabled.

### Explanation
An employee opened a fake update and attackers copied documents.

### Mitigation
### Immediate containment
1. Isolate the host
2. Block 185.244.25.17

### Best Practices
- Enable MFA

### Disclaimer
AI-generated, needs professional review.
"""


class FakeMessage:
    def __init__(self, content):
        self.content = content


class FakeLLM:
    def __init__(self, reply=GOOD_REPLY, error=None):
        self.reply, self.error, self.prompts = reply, error, []

    def invoke(self, prompt):
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return FakeMessage(self.reply)


def rest_incidents():
    return [to_common_format(n, "SOC").to_dict() for n in SAMPLE_INCIDENTS]


def kb_incident():
    with open(os.path.join(ROOT, "sample_data", "KnowledgeBase.txt"), encoding="utf-8") as handle:
        return FileUploadConnector("KB", "KnowledgeBase.txt", handle.read()).fetch_incidents()[0].to_dict()


class DashboardDataTests(unittest.TestCase):
    def test_threat_level_uses_active_incidents_only(self):
        incidents = rest_incidents()
        self.assertEqual(dd.overall_threat_level([]), "NO_DATA")
        self.assertEqual(dd.overall_threat_level(incidents), "CRITICAL")     # INC-3 is critical and open
        only_contained = [i for i in incidents if i["id"] == "INC-2026-0001"]  # critical but contained
        self.assertEqual(dd.overall_threat_level(only_contained), "CONTAINED")
        medium_open = [i for i in incidents if i["id"] == "INC-2026-0004"]
        self.assertEqual(dd.overall_threat_level(medium_open), "MEDIUM")

    def test_unknown_severity_is_never_reassuring(self):
        incident = {"id": "x", "severity": "Unknown", "status": "Open"}
        self.assertEqual(dd.overall_threat_level([incident]), "UNKNOWN")

    def test_counts(self):
        incidents = rest_incidents()
        all_counts = dd.severity_counts(incidents)
        self.assertEqual(all_counts, {"Critical": 2, "High": 1, "Medium": 1, "Low": 0, "Unknown": 0})
        active = dd.severity_counts(incidents, active_only=True)
        self.assertEqual(active["Critical"], 1)      # INC-1 is contained

    def test_private_ip_detection(self):
        for ip in ("10.0.0.1", "172.16.5.5", "172.31.0.1", "192.168.1.1", "127.0.0.1"):
            self.assertTrue(dd.is_private_ip(ip), ip)
        for ip in ("8.8.8.8", "172.32.0.1", "185.244.25.17", "not-an-ip", "1.2.3"):
            self.assertFalse(dd.is_private_ip(ip), ip)

    def test_top_indicators_count_incidents_not_mentions(self):
        incidents = [
            {"indicators": {"ips": ["1.1.1.1", "1.1.1.1", "2.2.2.2"]}},
            {"indicators": {"ips": ["1.1.1.1"]}},
        ]
        self.assertEqual(dd.top_indicators(incidents, "ips"), [("1.1.1.1", 2), ("2.2.2.2", 1)])

    def test_external_ips_and_techniques(self):
        incidents = rest_incidents()
        self.assertEqual(dd.external_ip_count(incidents), 4)   # 185.., 45.., 203.0.113.45, 198.51.100.23
        techniques = dd.technique_counts(incidents)
        self.assertEqual(techniques[0][0], "T1078")            # used by three incidents
        self.assertEqual(techniques[0][2], 3)

    def test_host_summary(self):
        rows = dd.host_summary(rest_incidents())
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["Worst severity"], "Critical")

    def test_sort_newest_first(self):
        ids = [i["id"] for i in dd.sort_incidents(rest_incidents())]
        self.assertEqual(ids[0], "INC-2026-0004")
        self.assertEqual(ids[-1], "INC-2026-0001")


class AIAnalysisTests(unittest.TestCase):
    def test_prompt_contains_the_facts_and_the_format(self):
        prompt = ai.build_prompt(rest_incidents()[0])
        for text in ("INC-2026-0001", "FINANCE-PC-07", "185.244.25.17", "T1059.001 (PowerShell)",
                     "Data exfiltration started", "### Mitigation", "Use ONLY the incident data"):
            self.assertIn(text, prompt)

    def test_uploaded_report_excerpt_is_capped(self):
        incident = kb_incident()
        prompt = ai.build_prompt(incident)
        self.assertIn("Excerpt of the original report", prompt)
        self.assertLess(len(prompt), ai.RAW_EXCERPT_LIMIT + 5000)

    def test_parse_sections(self):
        sections = ai.parse_sections(GOOD_REPLY)
        self.assertEqual(list(sections), ai.SECTION_ORDER)
        self.assertTrue(sections["Attack Type"].startswith("Phishing"))
        # a sub-heading inside a section stays inside it
        self.assertIn("### Immediate containment", sections["Mitigation"])
        self.assertIn("Block 185.244.25.17", sections["Mitigation"])

    def test_parse_sections_tolerates_decoration(self):
        text = "## **Incident Summary**\nOne.\n\n### Attack Type:\nTwo.\n"
        self.assertEqual(ai.parse_sections(text), {"Incident Summary": "One.", "Attack Type": "Two."})

    def test_analyze_success(self):
        llm = FakeLLM()
        result = ai.analyze(rest_incidents()[0], llm, "fake-model")
        self.assertTrue(result["format_ok"])
        self.assertEqual(len(result["sections"]), 8)
        self.assertEqual(result["model"], "fake-model")
        self.assertEqual(len(llm.prompts), 1)

    def test_analyze_keeps_answer_when_format_is_ignored(self):
        result = ai.analyze(rest_incidents()[0], FakeLLM("Just some free text answer."))
        self.assertFalse(result["format_ok"])
        self.assertEqual(result["sections"], {"Explanation": "Just some free text answer."})

    def test_list_content_is_joined(self):
        class ListLLM:
            def invoke(self, prompt):
                return FakeMessage([{"type": "text", "text": "### Attack Type\nA"}, {"type": "text", "text": "\nB"}])
        self.assertIn("A", ai.call_llm(ListLLM(), "p"))

    def test_empty_answer_is_an_error(self):
        with self.assertRaises(ai.AIError):
            ai.analyze(rest_incidents()[0], FakeLLM("   "))

    def test_friendly_errors(self):
        cases = {
            "400 API key not valid. Please pass a valid API key.": "API key",
            "Error code: 429 - rate limit reached": "rate limit",
            "404 model not found": "model name",
            "Connection error": "internet",
        }
        for raw, expected in cases.items():
            with self.assertRaises(ai.AIError) as ctx:
                ai.analyze(rest_incidents()[0], FakeLLM(error=RuntimeError(raw)))
            self.assertIn(expected.lower(), str(ctx.exception).lower(), raw)

    def test_missing_key(self):
        with self.assertRaises(ai.AIError):
            ai.get_llm("Gemini", "", "some-model")


class PdfTests(unittest.TestCase):
    def test_pdf_for_rest_and_file_incidents(self):
        sections = ai.parse_sections(GOOD_REPLY)
        for incident in (rest_incidents()[0], kb_incident()):
            pdf = build_pdf_report(incident, sections, "fake-model")
            self.assertTrue(pdf.startswith(b"%PDF"))
            self.assertGreater(len(pdf), 3000)

    def test_pdf_survives_awkward_text(self):
        nasty = {"Incident Summary": "Tom & Jerry <script>alert(1)</script> **bold** → arrow ✓ emoji 🔥",
                 "Mitigation": "### Heading\n1. one\n- two\n* three"}
        pdf = build_pdf_report(rest_incidents()[1], nasty)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_pdf_without_analysis(self):
        self.assertTrue(build_pdf_report(rest_incidents()[2], {}).startswith(b"%PDF"))

    def test_text_helpers(self):
        self.assertEqual(pdf_safe("a → b ✓ 🔥"), "a -> b  ")
        self.assertEqual(inline_markup("**hi** <b> & co"), "<b>hi</b> &lt;b&gt; &amp; co")


class DemoHelperTests(unittest.TestCase):
    def test_create_test_incident_over_http(self):
        with FakeServer() as server:
            connector = RestApiConnector("Demo", server.url, API_KEY)
            created = connector.create_test_incident()
            self.assertEqual(created.status, "Open")
            self.assertEqual(len(connector.fetch_incidents()), 5)


if __name__ == "__main__":
    unittest.main()

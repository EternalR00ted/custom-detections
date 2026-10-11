import copy
import unittest

from scripts import rules
from scripts.common import ROOT, Fail

LAB_RULE = ROOT / "detections" / "lab" / "defender-exclusion-added-from-command-line.yaml"


def lab_rule():
    return copy.deepcopy(rules.load(LAB_RULE))


class StaticChecks(unittest.TestCase):
    def test_lab_rule_passes(self):
        self.assertEqual(rules.problems(lab_rule(), LAB_RULE), [])
        sigma = rules.sigma_path(LAB_RULE, "defender-exclusion-added-from-command-line")
        self.assertEqual(rules.sigma_problems(sigma, "defender-exclusion-added-from-command-line"), [])

    def test_missing_and_unknown_fields(self):
        rule = lab_rule()
        del rule["severity"]
        rule["automatedActions"] = {"isolateDevices": []}
        found = rules.problems(rule)
        self.assertIn("missing severity", found)
        self.assertTrue(any("unknown field automatedActions" in p for p in found))

    def test_bad_values(self):
        rule = lab_rule()
        rule.update(id="Bad_ID", name="no source here", severity="critical", frequency="PT5M",
                    status="live", version="1.0")
        rule["tactics"] = [{"tactic": "Hacking", "techniques": ["T1"]}]
        found = " | ".join(rules.problems(rule))
        for text in ("id must be", "name must look like", "severity must be", "frequency must be",
                     "status must be", "version must look", "tactic must be"):
            self.assertIn(text, found)

    def test_file_name_must_match_id(self):
        rule = lab_rule()
        found = rules.problems(rule, ROOT / "detections" / "lab" / "other-name.yaml")
        self.assertIn("file name must be defender-exclusion-added-from-command-line.yaml", found)

    def test_entities(self):
        rule = lab_rule()
        rule["entities"] = {"hosts": [{"deviceIdColumn": "DeviceId", "colorColumn": "x"}], "planets": []}
        found = " | ".join(rules.problems(rule))
        self.assertIn("hosts entity has no setting colorColumn", found)
        self.assertIn("entity type planets isn't supported", found)

    def test_lab_tests_must_be_allowlisted(self):
        rule = lab_rule()
        rule["lab_tests"] = ["00000000-0000-0000-0000-000000000000"]
        self.assertTrue(any("isn't in config/atomics.yaml" in p for p in rules.problems(rule)))


class Kql(unittest.TestCase):
    def test_strings_and_comments_are_ignored(self):
        query = ('DeviceProcessEvents // externaldata in a comment\n'
                 '| where ProcessCommandLine has "Invoke-Expression" or ProcessCommandLine has @"evaluate"\n'
                 "| where FileName == 'http_request.exe'")
        self.assertEqual(rules.kql_problems(query), [])

    def test_blocked_operators(self):
        query = "DeviceProcessEvents\n| evaluate bag_unpack(AdditionalFields)\n| join (externaldata(x:string) [@'https://x'])"
        found = " | ".join(rules.kql_problems(query))
        self.assertIn("blocked KQL: evaluate", found)
        self.assertIn("blocked KQL: externaldata", found)

    def test_tables(self):
        self.assertEqual(rules.tables_in("DeviceProcessEvents | join DeviceNetworkEvents on DeviceId"),
                         {"DeviceProcessEvents", "DeviceNetworkEvents"})
        found = " | ".join(rules.kql_problems("EmailEvents | where Subject has 'x'"))
        self.assertIn("table that isn't allowed: EmailEvents", found)
        self.assertIn("doesn't query any allowed table", found)
        self.assertIn("wildcard union", " ".join(rules.kql_problems("union Device* | take 1")))

    def test_column_names_are_not_tables(self):
        self.assertEqual(rules.tables_in("DeviceProcessEvents | project DeviceId, DeviceName, ReportId"),
                         {"DeviceProcessEvents"})

    def test_production_and_window_queries(self):
        rule = lab_rule()
        query = rules.production_query(rule, "Detonation-VM")
        self.assertIn('== "detonation-vm"', query)
        self.assertIn('startswith strcat("detonation-vm", ".")', query)
        self.assertTrue(query.endswith("| summarize Hits = count()"))
        window = rules.window_query(rule, "detonation-vm", "2026-10-11T16:00:00Z", "2026-10-11T16:05:00Z")
        self.assertIn("datetime(2026-10-11T16:00:00Z) .. datetime(2026-10-11T16:05:00Z)", window)
        self.assertNotIn("not(", window)

    def test_lab_name_is_validated(self):
        with self.assertRaises(Fail):
            rules.production_query(lab_rule(), 'x" or 1==1 or "')


class GraphBody(unittest.TestCase):
    def test_body(self):
        body = rules.to_graph(lab_rule(), "Contoso")
        self.assertEqual(body["id"], "defender-exclusion-added-from-command-line")
        self.assertEqual(body["displayName"], "Contoso - MDE - Defender exclusion added from the command line")
        self.assertEqual(body["status"], "disabled")
        self.assertEqual(body["schedule"], {"frequency": "PT1H"})
        template = body["detectionAction"]["alertTemplate"]
        self.assertEqual(template["title"], body["displayName"])
        self.assertEqual(template["tactics"], [{"tactic": "DefenseEvasion", "techniques": [{"technique": "T1562.001"}]}])
        self.assertEqual(template["entityMappings"]["hosts"], [{"deviceIdColumn": "DeviceId", "nameColumn": "DeviceName"}])
        self.assertNotIn("automatedActions", body["detectionAction"])
        self.assertNotIn("isEnabled", body)

    def test_status_mapping(self):
        rule = lab_rule()
        rule["status"] = "production"
        self.assertEqual(rules.to_graph(rule, "")["status"], "enabled")
        self.assertEqual(rules.to_graph(rule, "")["displayName"], rule["name"])

    def test_schema_problems(self):
        rule = lab_rule()
        found = rules.schema_problems(rule, ["Timestamp", "DeviceId", "DeviceName"])
        self.assertIn("results must include column ReportId", found)
        self.assertIn("entity mapping uses column AccountSid, which the query doesn't return", found)


class Sigma(unittest.TestCase):
    def test_text_checks(self):
        self.assertIn("Sigma version is empty", rules.sigma_text_problems("", "x"))
        found = rules.sigma_text_problems("title: t\nlogsource: {}\ndetection: {condition: sel}\n", "x")
        self.assertIn("Sigma needs a logsource", found)
        self.assertIn("Sigma detection needs at least one selection besides the condition", found)


if __name__ == "__main__":
    unittest.main()

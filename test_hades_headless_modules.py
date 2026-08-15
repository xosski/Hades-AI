import tempfile
import unittest
from pathlib import Path

from hades_headless_modules import HeadlessModuleBridge
from payload_generator_core import PayloadGenerator
from payload_mutator import PayloadMutator


class HeadlessModuleTests(unittest.TestCase):
    def test_payload_catalog_has_no_gui_dependency(self):
        self.assertGreater(len(PayloadGenerator.get_payloads("sql")), 0)
        bridge = HeadlessModuleBridge(tempfile.mkdtemp())
        for vulnerability_type in ("sql_injection", "xss", "path_traversal"):
            catalog = bridge.payload_catalog(vulnerability_type)
            self.assertGreater(len(catalog), 0)
            self.assertTrue(all("payload" in item and "score" in item for item in catalog))
        self.assertTrue(bridge.payload_catalog("path_traversal")[0]["payload"].startswith("../"))

    def test_mutator_returns_generated_variants(self):
        variants = PayloadMutator().generate_mutations("<script>alert(1)</script>")
        self.assertGreater(len(variants), 0)
        self.assertTrue(all(item.mutated != item.original for item in variants))

    def test_knowledge_search_works_with_empty_databases(self):
        with tempfile.TemporaryDirectory() as root:
            result = HeadlessModuleBridge(root).search_knowledge("CVE-2099-0001")
            self.assertEqual(result, {"exploits": [], "cves": []})

    def test_cve_database_initializes_and_round_trips(self):
        from cve_integration import CVEDatabase, CVERecord
        with tempfile.TemporaryDirectory() as root:
            database = CVEDatabase(str(Path(root) / "cve.db"))
            record = CVERecord("CVE-2099-0001", "Example", "HIGH", 8.0, "vector",
                               ["example"], "2099-01-01", "2099-01-02",
                               ["https://example.test"], ["CWE-79"])
            database.store_cve(record)
            reloaded = CVEDatabase(str(Path(root) / "cve.db"))
            self.assertEqual(reloaded.search_by_cve_id(record.cve_id).description, "Example")


if __name__ == "__main__":
    unittest.main()

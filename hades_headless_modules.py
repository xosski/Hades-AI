"""Headless adapters for Hades modules used by the browser companion."""
from dataclasses import asdict
from pathlib import Path


class HeadlessModuleBridge:
    """Lazy, JSON-safe boundary around non-GUI Hades capabilities."""

    MODULES = {
        "payloads": "Payload catalog, mutation, and confidence scoring",
        "exploit_tome": "Local exploit knowledge lookup",
        "cve": "Local CVE lookup and finding enrichment",
        "cache": "Browser-cache finding history",
        "validation": "Evidence and confidence validation",
        "active_tests": "Deterministic SQLi, XSS, and traversal checks",
        "payload_sender": "Same-origin payload request sender",
        "port_scan": "Asynchronous TCP-connect port scanner",
        "llm": "Multi-provider Hades AI conversations",
    }

    def __init__(self, data_root=None):
        self.data_root = Path(data_root or Path(__file__).resolve().parent)
        from hades_network_tools import PortScanManager
        self.port_scans = PortScanManager()

    def capabilities(self):
        checks = {
            "payloads": ("payload_service", "PayloadService"),
            "exploit_tome": ("exploit_tome", "ExploitTome"),
            "cve": ("cve_integration", "CVEDatabase"),
            "cache": ("cache_scanner_enhanced", "EnhancedCacheScanner"),
            "validation": ("validation_enforcement", "ComplianceReport"),
            "active_tests": ("enhanced_vulnerability_tester", "EnhancedVulnerabilityTester"),
            "payload_sender": ("hades_network_tools", "send_test_payload"),
            "port_scan": ("hades_network_tools", "PortScanManager"),
            "llm": ("llm_conversation_core", "ConversationManager"),
        }
        result = []
        for module_id, (module_name, symbol) in checks.items():
            try:
                module = __import__(module_name, fromlist=[symbol])
                getattr(module, symbol)
                result.append({"id": module_id, "name": self.MODULES[module_id], "available": True})
            except Exception as error:
                result.append({"id": module_id, "name": self.MODULES[module_id],
                               "available": False, "reason": str(error)[:300]})
        return result

    def payload_catalog(self, vulnerability_type):
        from payload_service import PayloadService
        service = PayloadService()
        payloads = service.get_payloads_for_vulnerability(vulnerability_type)
        scored = service.get_scored_payloads(payloads, vulnerability_type)
        return [{"payload": payload, "score": round(score, 4), "rank": rank}
                for rank, (payload, score) in enumerate(scored, 1)]

    def mutate_payload(self, payload, technology=None, target_waf=None, limit=10):
        from payload_mutator import PayloadMutator
        mutations = PayloadMutator().generate_mutations(
            payload, technology=technology, target_waf=target_waf, max_mutations=limit)
        result = []
        for item in mutations:
            data = asdict(item)
            data["strategy"] = item.strategy.value
            result.append(data)
        return result

    def search_knowledge(self, query, limit=25):
        from cve_integration import CVEDatabase
        from exploit_tome import ExploitTome
        tome = ExploitTome(str(self.data_root / "exploit_tome.db"))
        try:
            exploits = [asdict(item) for item in tome.search_exploits(query)[:limit]]
        finally:
            tome.conn.close()
        cve_db = CVEDatabase(str(self.data_root / "cve_database.db"))
        if query.upper().startswith("CVE-"):
            record = cve_db.search_by_cve_id(query.upper())
            cves = [asdict(record)] if record else []
        else:
            cves = [asdict(item) for item in cve_db.search_by_product(query)[:limit]]
        return {"exploits": exploits, "cves": cves}

    def cache_summary(self, limit=25):
        from cache_scanner_enhanced import EnhancedCacheScanner
        scanner = EnhancedCacheScanner(str(self.data_root / "hades_knowledge.db"))
        try:
            return {"summary": scanner.get_threat_summary(),
                    "detections": scanner.get_cache_detections(limit)}
        finally:
            if scanner.conn:
                scanner.conn.close()

    def validate_finding(self, finding, allowed_origin):
        from validation_enforcement import ComplianceReport
        report = ComplianceReport()
        report.scope_validator.allowed_targets = {allowed_origin.split("://", 1)[1].split(":", 1)[0]}
        return report.validate_finding(dict(finding))

    def active_test(self, target_url, test_type, parameter):
        from enhanced_vulnerability_tester import EnhancedVulnerabilityTester
        tester = EnhancedVulnerabilityTester(timeout=10, verify_ssl=True)
        original_request = tester.session.request
        def no_redirect_request(*args, **kwargs):
            kwargs["allow_redirects"] = False
            return original_request(*args, **kwargs)
        tester.session.request = no_redirect_request
        methods = {"sql_injection": tester.test_sql_injection,
                   "xss": tester.test_xss,
                   "path_traversal": tester.test_path_traversal}
        if test_type not in methods:
            raise ValueError("Unsupported active test type")
        return asdict(methods[test_type](target_url, parameter))

    def send_payload(self, target_url, method, parameter, payload):
        from hades_network_tools import send_test_payload
        return send_test_payload(target_url, method, parameter, payload)

    def start_port_scan(self, host, start_port, end_port, timeout_ms):
        return self.port_scans.start(host, start_port, end_port, timeout_ms)

    def get_port_scan(self, job_id):
        return self.port_scans.get(job_id)

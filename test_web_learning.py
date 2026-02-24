"""
Test Suite for Web Knowledge Learning System
Tests knowledge extraction, storage, and AI enhancement
"""

import unittest
import json
import os
from datetime import datetime
from web_knowledge_learner import WebKnowledgeLearner, WebContentExtractor, WebKnowledgeStore
from ai_knowledge_enhancer import AIKnowledgeEnhancer, ChatAIKnowledgeMiddleware


class TestWebContentExtractor(unittest.TestCase):
    """Test CVE and exploit extraction from content"""
    
    def setUp(self):
        self.extractor = WebContentExtractor()
    
    def test_cve_extraction(self):
        """Test CVE pattern extraction"""
        content = """
        Security researchers discovered CVE-2024-1234 which is a critical vulnerability.
        It affects multiple versions and CVE-2024-5678 is related.
        """
        
        cves = self.extractor.extract_cves(content)
        
        self.assertGreater(len(cves), 0)
        self.assertEqual(cves[0]['cve_id'], 'CVE-2024-1234')
        self.assertIsNotNone(cves[0]['context'])
    
    def test_exploit_extraction(self):
        """Test exploit keyword extraction"""
        content = """
        The SQL injection payload is: ' OR '1'='1
        For RCE exploitation, send a specially crafted request.
        The shellcode can be injected via POST parameter.
        """
        
        exploits = self.extractor.extract_exploits(content, "http://test.com")
        
        self.assertGreater(len(exploits), 0)
        self.assertTrue(any('SQL' in e['type'] for e in exploits))
    
    def test_technique_extraction(self):
        """Test pentesting technique extraction"""
        content = """
        Enumeration phase: Start with reconnaissance and scanning
        Exploitation: Use the RCE vulnerability for code execution
        Privilege escalation through kernel exploits
        """
        
        techniques = self.extractor.extract_techniques(content, "http://test.com")
        
        self.assertGreater(len(techniques), 0)
        self.assertTrue(any('enumeration' in t['category'].lower() for t in techniques))
    
    def test_vulnerability_pattern_extraction(self):
        """Test vulnerability pattern detection"""
        content = """
        This application is vulnerable to SQL injection attacks.
        The XSS vulnerability allows script injection.
        CSRF protections are missing from the forms.
        """
        
        patterns = self.extractor.extract_vulnerability_patterns(content)
        
        self.assertGreater(len(patterns), 0)
        pattern_types = [p['pattern_type'] for p in patterns]
        self.assertTrue(any('SQL' in pt for pt in pattern_types))
        self.assertTrue(any('XSS' in pt for pt in pattern_types))
        self.assertTrue(any('CSRF' in pt for pt in pattern_types))
    
    def test_severity_extraction(self):
        """Test severity level extraction"""
        content_critical = "This vulnerability has a CVSS score of 9.8 (critical)"
        content_high = "Severity level is HIGH with CVSS 7.5"
        
        severity1 = self.extractor._extract_severity(content_critical)
        severity2 = self.extractor._extract_severity(content_high)
        
        self.assertEqual(severity1, 'CRITICAL')
        self.assertEqual(severity2, 'HIGH')


class TestWebKnowledgeStore(unittest.TestCase):
    """Test knowledge storage and retrieval"""
    
    @classmethod
    def setUpClass(cls):
        # Use test database
        cls.db_path = "test_knowledge.db"
        cls.store = WebKnowledgeStore(cls.db_path)
    
    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
    
    def test_store_cve(self):
        """Test storing CVE information"""
        cve_data = {
            'cve_id': 'CVE-2024-TEST',
            'severity': 'CRITICAL',
            'context': 'Test CVE context',
            'source_url': 'http://test.com',
            'summary': 'Test summary'
        }
        
        result = self.store.store_cve(cve_data)
        self.assertTrue(result)
        
        # Verify it was stored
        stats = self.store.get_learning_stats()
        self.assertGreater(stats['cves_learned'], 0)
    
    def test_store_exploit(self):
        """Test storing exploit information"""
        exploit_data = {
            'type': 'SQL_INJECTION',
            'code_snippet': "' OR '1'='1",
            'source_url': 'http://test.com'
        }
        
        result = self.store.store_exploit(exploit_data)
        self.assertTrue(result)
        
        stats = self.store.get_learning_stats()
        self.assertGreater(stats['exploits_learned'], 0)
    
    def test_store_technique(self):
        """Test storing technique information"""
        technique_data = {
            'category': 'enumeration',
            'name': 'PORT_SCANNING',
            'description': 'Scan target for open ports',
            'source_url': 'http://test.com'
        }
        
        result = self.store.store_technique(technique_data)
        self.assertTrue(result)
        
        stats = self.store.get_learning_stats()
        self.assertGreater(stats['techniques_learned'], 0)
    
    def test_store_vulnerability_pattern(self):
        """Test storing vulnerability pattern"""
        pattern_data = {
            'pattern_type': 'SQL_INJECTION',
            'signature': 'sql injection',
            'context': 'Found in user input',
            'source_url': 'http://test.com',
            'confidence': 0.95
        }
        
        result = self.store.store_vulnerability_pattern(pattern_data)
        self.assertTrue(result)
        
        stats = self.store.get_learning_stats()
        self.assertGreater(stats['patterns_learned'], 0)
    
    def test_learning_stats(self):
        """Test getting learning statistics"""
        stats = self.store.get_learning_stats()
        
        self.assertIn('cves_learned', stats)
        self.assertIn('exploits_learned', stats)
        self.assertIn('techniques_learned', stats)
        self.assertIn('patterns_learned', stats)
        self.assertIn('sources_processed', stats)


class TestWebKnowledgeLearner(unittest.TestCase):
    """Test the main learning system"""
    
    @classmethod
    def setUpClass(cls):
        cls.db_path = "test_learner.db"
        cls.learner = WebKnowledgeLearner(cls.db_path)
    
    @classmethod
    def tearDownClass(cls):
        cls.learner.close()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
    
    def test_learn_from_content(self):
        """Test full learning workflow"""
        content = """
        CVE-2024-LEARN is a critical vulnerability discovered recently.
        The SQL injection payload can bypass authentication.
        Attackers can achieve remote code execution through RCE techniques.
        """
        
        result = self.learner.learn_from_content(
            url="http://test.com/cve",
            content=content,
            metadata={'title': 'CVE Report'}
        )
        
        self.assertGreater(result['total_items_learned'], 0)
        self.assertTrue(len(result['cves']) > 0)
    
    def test_knowledge_context_retrieval(self):
        """Test retrieving knowledge for a query"""
        # First learn something
        content = "CVE-2024-CONTEXT is a SQL injection vulnerability"
        self.learner.learn_from_content(
            url="http://test.com/sql",
            content=content
        )
        
        # Now retrieve it
        context = self.learner.get_knowledge_context_for_query("SQL injection")
        
        self.assertIsInstance(context, str)
        self.assertGreater(len(context), 0)


class TestAIKnowledgeEnhancer(unittest.TestCase):
    """Test AI response enhancement"""
    
    @classmethod
    def setUpClass(cls):
        cls.db_path = "test_enhancer.db"
        cls.enhancer = AIKnowledgeEnhancer(cls.db_path)
        
        # Pre-populate with some knowledge
        test_content = """
        CVE-2024-ENHANCE is a critical vulnerability.
        SQL injection is a common attack vector.
        The exploit technique involves payload injection.
        """
        cls.enhancer.learner.learn_from_content(
            url="http://test.com/enhance",
            content=test_content
        )
    
    @classmethod
    def tearDownClass(cls):
        cls.enhancer.close()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
    
    def test_enhance_prompt(self):
        """Test prompt enhancement with knowledge"""
        user_query = "How do I test for SQL injection?"
        system_prompt = "You are a security expert"
        
        enhanced = self.enhancer.enhance_prompt(user_query, system_prompt)
        
        self.assertIn('system', enhanced)
        self.assertIn('user', enhanced)
        self.assertIn('has_context', enhanced)
        
        if enhanced['has_context']:
            self.assertIn('CONTEXT', enhanced['system'])
            self.assertIn('Learned', enhanced['system'])
    
    def test_learn_from_scan_results(self):
        """Test learning from scan results"""
        scan_results = {
            'vulnerabilities': [
                {'type': 'SQL Injection', 'cve': 'CVE-2024-SCAN'}
            ],
            'exploits': [
                {'type': 'SQLi', 'code': 'malicious code'}
            ],
            'raw_content': 'CVE-2024-SCAN is a critical SQL injection'
        }
        
        learning = self.enhancer.learn_from_scan_results(
            scan_results,
            source_url="http://target.com/scan"
        )
        
        self.assertGreater(learning['items_learned'], 0)
        self.assertEqual(learning['items_processed'], 3)
    
    def test_get_ai_response_with_knowledge(self):
        """Test enhancing AI response with knowledge"""
        user_query = "What is SQL injection?"
        ai_response = "SQL injection is when attackers insert malicious SQL code"
        
        enhanced = self.enhancer.get_ai_response_with_knowledge(user_query, ai_response)
        
        self.assertIsInstance(enhanced, str)
        self.assertGreater(len(enhanced), len(ai_response))
        self.assertIn(ai_response, enhanced)
    
    def test_learning_report(self):
        """Test generating learning report"""
        report = self.enhancer.create_learning_report()
        
        self.assertIsInstance(report, str)
        self.assertIn('LEARNING STATISTICS', report)
        self.assertIn('CVEs Learned', report)
        self.assertIn('Exploits Learned', report)
    
    def test_export_knowledge(self):
        """Test exporting learned knowledge"""
        export = self.enhancer.export_learned_knowledge('json')
        
        self.assertIsInstance(export, str)
        # Verify it's valid JSON
        data = json.loads(export)
        self.assertIn('cves', data)
        self.assertIn('exploits', data)
        self.assertIn('techniques', data)
        self.assertIn('patterns', data)


class TestChatAIKnowledgeMiddleware(unittest.TestCase):
    """Test chat integration middleware"""
    
    @classmethod
    def setUpClass(cls):
        cls.db_path = "test_middleware.db"
        cls.middleware = ChatAIKnowledgeMiddleware(db_path=cls.db_path)
        
        # Pre-populate knowledge
        content = "CVE-2024-CHAT is a critical vulnerability"
        cls.middleware.enhancer.learner.learn_from_content(
            url="http://test.com/chat",
            content=content
        )
    
    @classmethod
    def tearDownClass(cls):
        cls.middleware.close()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
    
    def test_process_user_message(self):
        """Test processing user message through middleware"""
        processed = self.middleware.process_user_message(
            user_message="How do I find vulnerabilities?",
            system_prompt="You are a security expert"
        )
        
        self.assertIn('original_query', processed)
        self.assertIn('enhanced_system', processed)
        self.assertIn('enhanced_user', processed)
        self.assertIn('has_context', processed)
    
    def test_process_llm_response(self):
        """Test processing LLM response through middleware"""
        response = self.middleware.process_llm_response(
            user_query="What is a vulnerability?",
            llm_response="A vulnerability is a security weakness"
        )
        
        self.assertIn('original_response', response)
        self.assertIn('enhanced_response', response)
        self.assertIn('knowledge_added', response)
        self.assertGreaterEqual(len(response['enhanced_response']), 
                               len(response['original_response']))
    
    def test_learn_from_interaction(self):
        """Test learning from chat interaction"""
        result = self.middleware.learn_from_interaction(
            user_query="What is a security vulnerability?",
            ai_response="A vulnerability is a weakness in security systems",
            metadata={'channel': 'test'}
        )
        
        self.assertIsInstance(result, bool)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflow"""
    
    @classmethod
    def setUpClass(cls):
        cls.db_path = "test_integration.db"
    
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
    
    def test_complete_learning_workflow(self):
        """Test complete workflow from learning to enhancement"""
        enhancer = AIKnowledgeEnhancer(self.db_path)
        
        # Step 1: Learn from security research
        research_content = """
        CVE-2024-INTEGRATION is a critical remote code execution vulnerability.
        The XSS vulnerability allows script injection attacks.
        Attackers can bypass authentication using SQL injection techniques.
        CVSS score: 9.8
        """
        
        learn_result = enhancer.learner.learn_from_content(
            url="http://security-research.com/report",
            content=research_content,
            metadata={'title': 'Security Research Report'}
        )
        
        self.assertGreater(learn_result['total_items_learned'], 0)
        
        # Step 2: Enhance a security question
        enhanced = enhancer.enhance_prompt(
            "How do I prevent remote code execution?",
            "You are a security consultant"
        )
        
        self.assertTrue(enhanced['has_context'])
        
        # Step 3: Check learning statistics
        stats = enhancer.learner.store.get_learning_stats()
        self.assertGreater(stats['cves_learned'], 0)
        self.assertGreater(stats['patterns_learned'], 0)
        
        # Step 4: Generate report
        report = enhancer.create_learning_report()
        self.assertIn('LEARNING STATISTICS', report)
        
        enhancer.close()


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestWebContentExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestWebKnowledgeStore))
    suite.addTests(loader.loadTestsFromTestCase(TestWebKnowledgeLearner))
    suite.addTests(loader.loadTestsFromTestCase(TestAIKnowledgeEnhancer))
    suite.addTests(loader.loadTestsFromTestCase(TestChatAIKnowledgeMiddleware))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)

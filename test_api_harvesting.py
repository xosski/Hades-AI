"""
Comprehensive tests for API testing & data harvesting
"""

import unittest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from api_testing_harvester import (
    DataPoint,
    APIEndpoint,
    APITestSession,
    APIEndpointDiscovery,
    DataHarvester,
    APITester,
    APITestReport
)


class TestDataHarvester(unittest.TestCase):
    """Test data extraction and classification"""
    
    def setUp(self):
        self.harvester = DataHarvester()
    
    def test_harvest_json_with_emails(self):
        """Test extracting email addresses from JSON"""
        data = {
            'users': [
                {'name': 'John', 'email': 'john@example.com'},
                {'name': 'Jane', 'email': 'jane@example.com'}
            ]
        }
        
        points = self.harvester.harvest_from_json(data, '/api/users')
        
        # Should find email addresses
        email_points = [p for p in points if p.data_type == 'email']
        self.assertGreater(len(email_points), 0)
        self.assertEqual(email_points[0].sensitivity, 'pii')
    
    def test_harvest_json_with_api_keys(self):
        """Test extracting API keys"""
        data = {
            'config': {
                'api_key': 'sk-1234567890abcdefghijklmnopqrstuv',
                'database_url': 'postgresql://user:pass@localhost/db'
            }
        }
        
        points = self.harvester.harvest_from_json(data, '/api/config')
        
        # Should classify credential/sensitive (api_key field name triggers sensitivity)
        sensitive = [p for p in points if p.sensitivity == 'sensitive' and 'api' in p.field_name.lower()]
        self.assertGreater(len(sensitive), 0, f"No sensitive fields found in: {[(p.field_name, p.sensitivity) for p in points]}")
    
    def test_harvest_text_with_ip_addresses(self):
        """Test extracting IP addresses from text"""
        text = """
        Server running on 192.168.1.1
        Internal IP: 10.0.0.5
        External IP: 8.8.8.8
        """
        
        points = self.harvester.harvest_from_text(text, '/api/status')
        
        ip_points = [p for p in points if p.data_type == 'ip_address']
        self.assertGreaterEqual(len(ip_points), 3)
    
    def test_classify_credit_card(self):
        """Test credit card detection"""
        dtype, sensitivity = self.harvester._classify_data('card_number', '4532-1111-2222-3333')
        self.assertEqual(sensitivity, 'sensitive')
    
    def test_classify_by_field_name(self):
        """Test classification by field name"""
        dtype, sensitivity = self.harvester._classify_data('password', 'secret123')
        self.assertEqual(sensitivity, 'sensitive')
        
        dtype, sensitivity = self.harvester._classify_data('api_key', 'key123')
        self.assertEqual(sensitivity, 'sensitive')
    
    def test_structural_data_detection(self):
        """Test important structural fields"""
        self.assertTrue(self.harvester._is_structural_data('user_id'))
        self.assertTrue(self.harvester._is_structural_data('admin'))
        self.assertTrue(self.harvester._is_structural_data('role'))
        self.assertFalse(self.harvester._is_structural_data('random_field'))


class TestAPIEndpointDiscovery(unittest.TestCase):
    """Test endpoint discovery"""
    
    def setUp(self):
        self.discoverer = APIEndpointDiscovery()
    
    def test_common_endpoints_list(self):
        """Test that common endpoints are defined"""
        self.assertGreater(len(self.discoverer.COMMON_ENDPOINTS), 10)
        self.assertIn('/api', self.discoverer.COMMON_PATTERNS)
        self.assertIn('/users', self.discoverer.COMMON_ENDPOINTS)
    
    @patch('requests.Session.get')
    def test_discover_endpoints(self, mock_get):
        """Test endpoint discovery with mocked requests"""
        # Mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        import requests
        session = requests.Session()
        
        endpoints = self.discoverer.discover_endpoints('http://localhost:8000', session)
        
        # Should have found some endpoints
        self.assertGreater(len(endpoints), 0)


class TestAPITester(unittest.TestCase):
    """Test main API testing functionality"""
    
    def setUp(self):
        self.tester = APITester('http://localhost:8000')
    
    def test_initialization(self):
        """Test tester initialization"""
        self.assertEqual(self.tester.base_url, 'http://localhost:8000')
        self.assertEqual(self.tester.timeout, 10)
        self.assertIsNotNone(self.tester.session)
    
    @patch('requests.Session.get')
    def test_endpoint_testing(self, mock_get):
        """Test single endpoint"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": "test"}'
        mock_response.text = '{"data": "test"}'
        mock_response.json.return_value = {'data': 'test'}
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        result = self.tester.test_endpoint('/api/users')
        
        self.assertEqual(result.response_code, 200)
        self.assertEqual(result.path, '/api/users')
        self.assertTrue(result.accessible)
    
    @patch('requests.Session.get')
    def test_endpoint_401_auth_detection(self, mock_get):
        """Test authentication requirement detection"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.content = b'Unauthorized'
        mock_response.text = 'Unauthorized'
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        result = self.tester.test_endpoint('/api/admin')
        
        self.assertEqual(result.response_code, 401)
        self.assertTrue(result.auth_required)
        self.assertFalse(result.accessible)
    
    @patch('requests.Session.get')
    def test_parameter_fuzzing(self, mock_get):
        """Test parameter fuzzing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"result": "found"}'
        mock_get.return_value = mock_response
        
        results = self.tester.parameter_fuzzing('/api/search', param_names=['id', 'debug'])
        
        # Should test multiple parameter values
        self.assertGreater(len(results), 5)
    
    @patch('requests.Session.get')
    def test_injection_vulnerability_testing(self, mock_get):
        """Test injection payload detection"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Error: SQL syntax error near line 1'
        mock_response.content = b'error'
        mock_get.return_value = mock_response
        
        results = self.tester.test_injection_vulnerabilities('/api/search')
        
        # Should have tested SQL injection
        sql_tests = [r for r in results if r['type'] == 'sql']
        self.assertGreater(len(sql_tests), 0)


class TestAPITestSession(unittest.TestCase):
    """Test session tracking"""
    
    def test_session_creation(self):
        """Test creating test session"""
        session = APITestSession(base_url='http://localhost:8000')
        
        self.assertEqual(session.base_url, 'http://localhost:8000')
        self.assertEqual(len(session.endpoints_tested), 0)
        self.assertEqual(session.total_data_points, 0)
    
    def test_session_to_dict(self):
        """Test serialization"""
        session = APITestSession(base_url='http://localhost:8000')
        
        endpoint = APIEndpoint(
            path='/api/users',
            method='GET',
            response_code=200,
            response_time=0.5
        )
        session.endpoints_tested.append(endpoint)
        
        result = session.to_dict()
        
        self.assertEqual(result['base_url'], 'http://localhost:8000')
        self.assertEqual(result['endpoints_tested'], 1)
        self.assertIn('endpoints', result)


class TestDataHarvestingIntegration(unittest.TestCase):
    """Integration tests for full harvesting flow"""
    
    @patch('requests.Session.get')
    def test_full_harvest_workflow(self, mock_get):
        """Test complete harvesting workflow"""
        # Mock complex response with sensitive data
        response_data = {
            'users': [
                {
                    'id': 1,
                    'name': 'Admin',
                    'email': 'admin@company.com',
                    'api_key': 'sk-abc123def456ghi789jkl',
                    'role': 'administrator',
                    'is_admin': True
                },
                {
                    'id': 2,
                    'name': 'User',
                    'email': 'user@company.com',
                    'ip_address': '192.168.1.100'
                }
            ],
            'config': {
                'database_url': 'postgresql://admin:password123@db.internal:5432/prod',
                'debug': True
            }
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(response_data).encode()
        mock_response.text = json.dumps(response_data)
        mock_response.json.return_value = response_data
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        tester = APITester('http://localhost:8000')
        result = tester.test_endpoint('/api/users')
        
        # Should harvest data
        self.assertGreater(len(result.data_harvested), 0)
        
        # Should detect sensitive data
        sensitive_points = [p for p in result.data_harvested 
                           if p.sensitivity in ['sensitive', 'pii']]
        self.assertGreater(len(sensitive_points), 0)
        
        # Check for specific findings
        data_types = {p.data_type for p in result.data_harvested}
        # api_key or credential both acceptable
        self.assertTrue('api_key' in data_types or 'credential' in data_types)


class TestAPITestReporting(unittest.TestCase):
    """Test report generation"""
    
    def setUp(self):
        self.session = APITestSession(base_url='http://localhost:8000')
        
        # Add test endpoints
        endpoint = APIEndpoint(
            path='/api/users',
            method='GET',
            response_code=200,
            response_time=0.5
        )
        
        endpoint.data_harvested.append(DataPoint(
            path='email',
            field_name='email',
            field_value='admin@company.com',
            data_type='email',
            sensitivity='pii',
            source_endpoint='/api/users'
        ))
        
        endpoint.data_harvested.append(DataPoint(
            path='api_key',
            field_name='api_key',
            field_value='sk-abc123...',
            data_type='api_key',
            sensitivity='sensitive',
            source_endpoint='/api/users'
        ))
        
        self.session.endpoints_tested.append(endpoint)
        self.session.total_data_points = 2
        self.session.sensitivity_breakdown = {'pii': 1, 'sensitive': 1}
        self.session.data_types_found = {'email': 1, 'api_key': 1}
    
    def test_summary_report(self):
        """Test summary report generation"""
        report = APITestReport.generate_summary(self.session)
        
        self.assertIn('API SECURITY POSTURE ASSESSMENT REPORT', report)
        self.assertIn('http://localhost:8000', report)
        self.assertIn('Total data points found: 2', report)
        self.assertIn('PII', report)
        self.assertIn('SENSITIVE', report)
        self.assertIn('SECURITY INFRASTRUCTURE', report)
    
    def test_json_report(self):
        """Test JSON report generation"""
        report = APITestReport.generate_json(self.session)
        data = json.loads(report)
        
        self.assertEqual(data['base_url'], 'http://localhost:8000')
        self.assertEqual(data['total_data_points'], 2)
        self.assertIn('sensitivity_breakdown', data)
    
    def test_export_harvested_data(self):
        """Test data export"""
        export = APITestReport.export_harvested_data(self.session)
        
        self.assertEqual(len(export), 2)
        self.assertEqual(export[0]['endpoint'], '/api/users')
        self.assertEqual(export[0]['sensitivity'], 'pii')
        self.assertIn('value_preview', export[0])


class TestDataPointExport(unittest.TestCase):
    """Test data point serialization"""
    
    def test_datapoint_serialization(self):
        """Test DataPoint to dict conversion"""
        point = DataPoint(
            path='users[0].email',
            field_name='email',
            field_value='test@example.com',
            data_type='email',
            sensitivity='pii',
            source_endpoint='/api/users'
        )
        
        result = point.to_dict()
        
        self.assertEqual(result['field_name'], 'email')
        self.assertEqual(result['sensitivity'], 'pii')
        self.assertEqual(result['source_endpoint'], '/api/users')


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def setUp(self):
        self.tester = APITester('http://localhost:8000')
    
    @patch('requests.Session.get')
    def test_connection_error_handling(self, mock_get):
        """Test handling connection errors"""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = self.tester.test_endpoint('/api/test')
        
        self.assertIsNotNone(result.error)
        self.assertEqual(result.response_code, 0)
    
    @patch('requests.Session.get')
    def test_timeout_handling(self, mock_get):
        """Test handling timeouts"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = self.tester.test_endpoint('/api/slow')
        
        self.assertEqual(result.error, "Timeout")
    
    @patch('requests.Session.get')
    def test_malformed_json_handling(self, mock_get):
        """Test handling malformed JSON"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'not json'
        mock_response.text = 'not json'
        mock_response.json.side_effect = ValueError()
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        result = self.tester.test_endpoint('/api/bad')
        
        # Should fallback to text extraction
        self.assertEqual(result.response_code, 200)


class TestSensitivityClassification(unittest.TestCase):
    """Test data sensitivity classification"""
    
    def setUp(self):
        self.harvester = DataHarvester()
    
    def test_pii_classification(self):
        """Test PII data classification"""
        # Email
        dtype, sens = self.harvester._classify_data('email', 'user@example.com')
        self.assertEqual(sens, 'pii')
        
        # Phone
        dtype, sens = self.harvester._classify_data('phone', '555-1234-5678')
        self.assertEqual(sens, 'pii')
        
        # SSN
        dtype, sens = self.harvester._classify_data('ssn', '123-45-6789')
        self.assertEqual(sens, 'sensitive')
    
    def test_sensitive_data_classification(self):
        """Test sensitive data classification"""
        # API Key
        dtype, sens = self.harvester._classify_data('api_key', 'sk-abc123def456')
        self.assertEqual(sens, 'sensitive')
        
        # Password
        dtype, sens = self.harvester._classify_data('password', 'SecretPass123')
        self.assertEqual(sens, 'sensitive')
        
        # Credit card
        dtype, sens = self.harvester._classify_data('card', '4532-1111-2222-3333')
        self.assertEqual(sens, 'sensitive')
    
    def test_internal_data_classification(self):
        """Test internal data classification"""
        # Hash
        dtype, sens = self.harvester._classify_data('hash', 'abc123def456abc123def456abc123de')
        self.assertEqual(sens, 'internal')
        
        # Token
        dtype, sens = self.harvester._classify_data('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
        self.assertEqual(sens, 'internal')


def run_tests():
    """Run all tests"""
    unittest.main(verbosity=2)


if __name__ == '__main__':
    run_tests()

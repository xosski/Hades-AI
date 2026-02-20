"""
API Testing & Data Harvesting Module
Tests API endpoints, traverses API paths, and reports exact data harvested
"""

import requests
import json
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse
import logging
from collections import defaultdict
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class DataPoint:
    """Represents a single piece of harvested data"""
    path: str
    field_name: str
    field_value: str
    data_type: str
    sensitivity: str  # public, internal, sensitive, pii
    source_endpoint: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        return {
            'path': self.path,
            'field_name': self.field_name,
            'field_value': self.field_value,
            'data_type': self.data_type,
            'sensitivity': self.sensitivity,
            'source_endpoint': self.source_endpoint,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class APIEndpoint:
    """Represents an API endpoint"""
    path: str
    method: str
    response_code: int
    response_time: float
    data_harvested: List[DataPoint] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    body_size: int = 0
    auth_required: bool = False
    accessible: bool = False
    error: Optional[str] = None
    waf_detected: bool = False
    waf_name: Optional[str] = None
    blocked_by_waf: bool = False
    set_cookies: List[str] = field(default_factory=list)
    server_info: Optional[str] = None
    edge_detected: bool = False
    
    def to_dict(self):
        return {
            'path': self.path,
            'method': self.method,
            'response_code': self.response_code,
            'response_time': self.response_time,
            'body_size': self.body_size,
            'auth_required': self.auth_required,
            'accessible': self.accessible,
            'data_points_count': len(self.data_harvested),
            'data_harvested': [d.to_dict() for d in self.data_harvested],
            'error': self.error,
            'waf_detected': self.waf_detected,
            'waf_name': self.waf_name,
            'blocked_by_waf': self.blocked_by_waf,
            'set_cookies': self.set_cookies,
            'server_info': self.server_info,
            'edge_detected': self.edge_detected
        }


@dataclass
class APITestSession:
    """Complete test session for an API"""
    base_url: str
    timestamp: datetime = field(default_factory=datetime.now)
    endpoints_tested: List[APIEndpoint] = field(default_factory=list)
    total_data_points: int = 0
    sensitivity_breakdown: Dict[str, int] = field(default_factory=dict)
    data_types_found: Dict[str, int] = field(default_factory=dict)
    vulnerabilities_found: List[Dict] = field(default_factory=list)
    
    def to_dict(self):
        return {
            'base_url': self.base_url,
            'timestamp': self.timestamp.isoformat(),
            'endpoints_tested': len(self.endpoints_tested),
            'total_data_points': self.total_data_points,
            'sensitivity_breakdown': self.sensitivity_breakdown,
            'data_types_found': self.data_types_found,
            'vulnerabilities_found': self.vulnerabilities_found,
            'endpoints': [e.to_dict() for e in self.endpoints_tested]
        }


# ============================================================================
# WAF & SECURITY INFRASTRUCTURE DETECTION
# ============================================================================

class WAFDetector:
    """Detects WAF and security infrastructure"""
    
    # WAF signatures in headers
    WAF_SIGNATURES = {
        'cloudflare': ['cf-ray', 'cf-mitigated', 'cf-request-id', 'server: cloudflare'],
        'akamai': ['akamai-origin-hop', 'via: akamai', 'x-akamai'],
        'modsecurity': ['modsecurity', 'OWASP ModSecurity'],
        'imperva': ['x-iinfo', 'x-edge-location', 'incapsula'],
        'barracuda': ['barracuda', 'barra_counter'],
        'f5': ['x-wa-info', 'x-paddle'],
        'aws_waf': ['x-amzn-waf', 'x-amz'],
        'fortinet': ['fortiweb'],
        'sucuri': ['x-sucuri-id', 'sucuri'],
        'wordfence': ['wordfence'],
    }
    
    BLOCKING_INDICATORS = {
        403: ['Forbidden', 'Access Denied', 'Blocked'],
        429: ['Too Many Requests', 'Rate Limited'],
        406: ['Not Acceptable'],
        418: ['I\'m a teapot'],
    }
    
    @staticmethod
    def detect_waf(response_headers: Dict, response_status: int) -> Tuple[bool, Optional[str], bool]:
        """
        Detect WAF presence
        Returns: (waf_detected, waf_name, is_blocking)
        """
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        # Check for 403 Forbidden (often WAF blocking)
        blocked = response_status == 403
        
        # Check WAF signatures
        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for sig in signatures:
                for header_key, header_value in headers_lower.items():
                    if sig in f"{header_key}: {header_value}":
                        return True, waf_name, blocked
        
        return False, None, blocked
    
    @staticmethod
    def detect_edge(response_headers: Dict) -> bool:
        """Detect if response came through edge/CDN"""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        edge_indicators = ['cf-', 'x-akamai', 'via:', 'x-cdn', 'x-edge', 'server: cloudflare']
        
        for key, value in headers_lower.items():
            for indicator in edge_indicators:
                if indicator in f"{key}: {value}".lower():
                    return True
        
        return False
    
    @staticmethod
    def extract_cookies(response_headers: Dict) -> List[str]:
        """Extract Set-Cookie headers (redacted)"""
        cookies = []
        
        for key, value in response_headers.items():
            if key.lower() == 'set-cookie':
                # Redact sensitive cookie values
                cookie_parts = value.split(';')
                redacted = f"{cookie_parts[0].split('=')[0]}=[REDACTED]"
                if len(cookie_parts) > 1:
                    redacted += "; " + "; ".join(cookie_parts[1:])
                cookies.append(redacted)
        
        return cookies
    
    @staticmethod
    def get_server_info(response_headers: Dict) -> Optional[str]:
        """Extract server identification"""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        server_info = headers_lower.get('server')
        if not server_info:
            server_info = headers_lower.get('x-powered-by')
        if not server_info:
            server_info = headers_lower.get('x-aspnet-version')
        
        return server_info


# ============================================================================
# API ENDPOINT DISCOVERY
# ============================================================================

class APIEndpointDiscovery:
    """Discovers API endpoints through common patterns"""
    
    COMMON_PATTERNS = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/v3',
        '/rest',
        '/graphql',
        '/rpc',
        '/.well-known',
    ]
    
    COMMON_ENDPOINTS = [
        '/users',
        '/user',
        '/profile',
        '/me',
        '/admin',
        '/config',
        '/settings',
        '/status',
        '/health',
        '/info',
        '/version',
        '/auth',
        '/login',
        '/logout',
        '/register',
        '/password',
        '/token',
        '/session',
        '/permissions',
        '/roles',
        '/groups',
        '/organizations',
        '/projects',
        '/teams',
        '/data',
        '/export',
        '/import',
        '/backup',
        '/logs',
        '/debug',
        '/swagger',
        '/api-docs',
        '/docs',
    ]
    
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    def discover_endpoints(self, base_url: str, session: requests.Session = None) -> List[str]:
        """Discover available endpoints"""
        if session is None:
            session = requests.Session()
        
        discovered = []
        
        # Try common patterns and endpoints
        for pattern in self.COMMON_PATTERNS:
            for endpoint in self.COMMON_ENDPOINTS:
                url = urljoin(base_url, pattern + endpoint)
                try:
                    r = session.get(url, timeout=5, verify=False)
                    if r.status_code < 500:  # Not a server error
                        discovered.append(url)
                except:
                    pass
        
        return list(set(discovered))


# ============================================================================
# DATA HARVESTING & EXTRACTION
# ============================================================================

class DataHarvester:
    """Extracts and classifies data from responses"""
    
    # Patterns to detect sensitive data types
    PII_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(\+?\d{1,3}[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4,6}',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'api_key': r'sk-[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{40,}',
        'password': r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
        'hash': r'(?:hash|md5|sha1|sha256)["\']?\s*[:=]\s*["\']?([a-f0-9]{32,})',
        'token': r'(?:token|bearer|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_\.]{20,})',
    }
    
    SENSITIVITY_LEVELS = {
        'email': 'pii',
        'phone': 'pii',
        'ssn': 'sensitive',
        'credit_card': 'sensitive',
        'api_key': 'sensitive',
        'password': 'sensitive',
        'hash': 'internal',
        'token': 'internal',
        'ip_address': 'public',
    }
    
    def harvest_from_json(self, data: Dict, source_path: str) -> List[DataPoint]:
        """Extract data from JSON response"""
        points = []
        
        def extract_recursive(obj, prefix=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_path = f"{prefix}.{key}" if prefix else key
                    extract_recursive(value, full_path)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    full_path = f"{prefix}[{idx}]"
                    extract_recursive(item, full_path)
            else:
                # Check for PII/sensitive data
                points.append((prefix, str(obj)))
        
        extract_recursive(data)
        
        harvested = []
        for field_path, value in points:
            data_type, sensitivity = self._classify_data(field_path, value)
            
            if sensitivity != 'public' or self._is_structural_data(field_path):
                point = DataPoint(
                    path=field_path,
                    field_name=field_path.split('.')[-1] if '.' in field_path else field_path,
                    field_value=value[:100],  # Truncate for safety
                    data_type=data_type,
                    sensitivity=sensitivity,
                    source_endpoint=source_path
                )
                harvested.append(point)
        
        return harvested
    
    def harvest_from_text(self, text: str, source_path: str) -> List[DataPoint]:
        """Extract data from plain text response"""
        points = []
        
        for data_type, pattern in self.PII_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[0] if match[0] else match
                else:
                    value = match
                
                sensitivity = self.SENSITIVITY_LEVELS.get(data_type, 'public')
                point = DataPoint(
                    path=data_type,
                    field_name=data_type,
                    field_value=value[:100],
                    data_type=data_type,
                    sensitivity=sensitivity,
                    source_endpoint=source_path
                )
                points.append(point)
        
        return points
    
    def _classify_data(self, field_name: str, value: str) -> Tuple[str, str]:
        """Classify data type and sensitivity"""
        value_str = str(value).lower()
        field_lower = field_name.lower()
        
        # Check field names for sensitivity FIRST (takes precedence)
        if any(kw in field_lower for kw in ['password', 'passwd', 'pwd', 'secret']):
            return 'credential', 'sensitive'
        if any(kw in field_lower for kw in ['api_key', 'apikey', 'api-key', 'access_key', 'secret_key']):
            return 'api_key', 'sensitive'
        if any(kw in field_lower for kw in ['key']) and 'api' not in field_lower:
            return 'credential', 'sensitive'
        
        # Check PII patterns
        for data_type, pattern in self.PII_PATTERNS.items():
            if re.search(pattern, str(value)):
                return data_type, self.SENSITIVITY_LEVELS.get(data_type, 'public')
        if any(kw in field_lower for kw in ['token', 'auth', 'bearer']):
            return 'token', 'internal'
        if any(kw in field_lower for kw in ['email', 'mail']):
            return 'email', 'pii'
        if any(kw in field_lower for kw in ['phone', 'mobile', 'cellular']):
            return 'phone', 'pii'
        if any(kw in field_lower for kw in ['address', 'city', 'state', 'zipcode']):
            return 'address', 'pii'
        
        # Try to infer type from value
        if re.match(r'^\d+$', str(value)):
            return 'numeric', 'public'
        if re.match(r'^[a-f0-9]{32,}$', value_str):
            return 'hash', 'internal'
        
        return 'text', 'public'
    
    def _is_structural_data(self, field_path: str) -> bool:
        """Check if field contains structural/metadata"""
        important_fields = [
            'id', 'name', 'email', 'user', 'admin', 'role', 'permission',
            'token', 'key', 'secret', 'password', 'auth', 'credential',
            'endpoint', 'url', 'api', 'database', 'config', 'setting',
            'version', 'debug', 'enabled', 'internal'
        ]
        
        field_lower = field_path.lower()
        return any(kw in field_lower for kw in important_fields)


# ============================================================================
# API TESTING ENGINE
# ============================================================================

class APITester:
    """Main API testing and traversal engine"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.harvester = DataHarvester()
        self.discoverer = APIEndpointDiscovery()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (API-Tester)',
        })
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def test_endpoint(self, endpoint: str, method: str = 'GET', 
                     data: Dict = None, headers: Dict = None) -> APIEndpoint:
        """Test a single endpoint"""
        url = urljoin(self.base_url, endpoint)
        
        test_endpoint = APIEndpoint(
            path=endpoint,
            method=method,
            response_code=0,
            response_time=0
        )
        
        try:
            start = time.time()
            
            if method.upper() == 'GET':
                r = self.session.get(url, timeout=self.timeout, headers=headers)
            elif method.upper() == 'POST':
                r = self.session.post(url, json=data, timeout=self.timeout, headers=headers)
            elif method.upper() == 'PUT':
                r = self.session.put(url, json=data, timeout=self.timeout, headers=headers)
            elif method.upper() == 'DELETE':
                r = self.session.delete(url, timeout=self.timeout, headers=headers)
            elif method.upper() == 'PATCH':
                r = self.session.patch(url, json=data, timeout=self.timeout, headers=headers)
            else:
                r = self.session.request(method, url, timeout=self.timeout, headers=headers)
            
            test_endpoint.response_code = r.status_code
            test_endpoint.response_time = time.time() - start
            test_endpoint.body_size = len(r.content)
            test_endpoint.accessible = r.status_code < 400
            test_endpoint.headers = dict(r.headers)
            
            # Detect WAF/security infrastructure
            waf_detected, waf_name, is_blocking = WAFDetector.detect_waf(
                dict(r.headers), r.status_code
            )
            test_endpoint.waf_detected = waf_detected
            test_endpoint.waf_name = waf_name
            test_endpoint.blocked_by_waf = is_blocking
            test_endpoint.edge_detected = WAFDetector.detect_edge(dict(r.headers))
            test_endpoint.set_cookies = WAFDetector.extract_cookies(dict(r.headers))
            test_endpoint.server_info = WAFDetector.get_server_info(dict(r.headers))
            
            # Check auth requirement
            if r.status_code == 401:
                test_endpoint.auth_required = True
            
            # Harvest data (but skip if blocked by WAF)
            if not is_blocking:
                try:
                    json_data = r.json()
                    test_endpoint.data_harvested.extend(
                        self.harvester.harvest_from_json(json_data, endpoint)
                    )
                except:
                    # Try text extraction
                    test_endpoint.data_harvested.extend(
                        self.harvester.harvest_from_text(r.text, endpoint)
                    )
        
        except requests.exceptions.Timeout:
            test_endpoint.error = "Timeout"
        except requests.exceptions.ConnectionError:
            test_endpoint.error = "Connection Error"
        except Exception as e:
            test_endpoint.error = str(e)
        
        return test_endpoint
    
    def traverse_api(self, max_depth: int = 3, test_payloads: bool = True) -> APITestSession:
        """Traverse API and test endpoints"""
        session_data = APITestSession(base_url=self.base_url)
        
        # Discover endpoints
        endpoints = self.discoverer.discover_endpoints(self.base_url, self.session)
        
        # Test each discovered endpoint
        for endpoint in endpoints:
            relative_path = endpoint.replace(self.base_url, '')
            
            # Test with GET
            result = self.test_endpoint(relative_path, 'GET')
            session_data.endpoints_tested.append(result)
            
            # Try POST with empty payload
            if test_payloads:
                result = self.test_endpoint(relative_path, 'POST', data={})
                session_data.endpoints_tested.append(result)
        
        # Calculate stats
        all_data_points = []
        for endpoint in session_data.endpoints_tested:
            all_data_points.extend(endpoint.data_harvested)
        
        session_data.total_data_points = len(all_data_points)
        
        # Sensitivity breakdown
        sensitivity_map = defaultdict(int)
        for point in all_data_points:
            sensitivity_map[point.sensitivity] += 1
        session_data.sensitivity_breakdown = dict(sensitivity_map)
        
        # Data types found
        type_map = defaultdict(int)
        for point in all_data_points:
            type_map[point.data_type] += 1
        session_data.data_types_found = dict(type_map)
        
        return session_data
    
    def parameter_fuzzing(self, endpoint: str, param_names: List[str] = None) -> List[Dict]:
        """Fuzz common parameters"""
        common_params = [
            'id', 'user_id', 'username', 'email', 'search', 'query',
            'filter', 'sort', 'limit', 'offset', 'page', 'debug',
            'admin', 'role', 'permission', 'key', 'token', 'api_key'
        ]
        
        param_names = param_names or common_params
        test_values = [0, -1, 'admin', 'test', '123', '*.js', '../../../etc/passwd']
        
        results = []
        
        for param in param_names:
            for value in test_values:
                try:
                    url = urljoin(self.base_url, endpoint)
                    r = self.session.get(url, params={param: value}, timeout=self.timeout)
                    
                    # Detect interesting responses
                    interesting = (
                        r.status_code != 404 and
                        len(r.content) > 100 and
                        (r.status_code != 200 or 'error' in r.text.lower())
                    )
                    
                    results.append({
                        'parameter': param,
                        'value': value,
                        'status': r.status_code,
                        'response_size': len(r.content),
                        'interesting': interesting
                    })
                except Exception as e:
                    results.append({
                        'parameter': param,
                        'value': value,
                        'error': str(e)
                    })
        
        return results
    
    def test_injection_vulnerabilities(self, endpoint: str) -> List[Dict]:
        """Test for injection vulnerabilities"""
        injection_tests = {
            'sql': ["'; DROP TABLE users--", "' OR '1'='1", "admin'--"],
            'nosql': [
                {'$gt': ''},
                {'$ne': None},
                {'$regex': '.*'},
            ],
            'command': [
                '|whoami',
                '; cat /etc/passwd',
                '`id`',
                '$(whoami)',
            ],
            'path_traversal': [
                '/../../../etc/passwd',
                '..\\..\\..\\windows\\system32',
                '..\\..\\..',
            ]
        }
        
        results = []
        
        for injection_type, payloads in injection_tests.items():
            for payload in payloads:
                try:
                    url = urljoin(self.base_url, endpoint)
                    
                    # Try in different places
                    r = self.session.get(url, params={'q': payload}, timeout=self.timeout)
                    
                    results.append({
                        'type': injection_type,
                        'payload': str(payload),
                        'status': r.status_code,
                        'response_size': len(r.content),
                        'error_indicators': 'error' in r.text.lower() or 'sql' in r.text.lower()
                    })
                except:
                    pass
        
        return results


# ============================================================================
# REPORTING
# ============================================================================

class APITestReport:
    """Generates comprehensive test reports"""
    
    @staticmethod
    def generate_summary(session: APITestSession) -> str:
        """Generate text summary focusing on security posture, not exploitation"""
        report = []
        report.append("=" * 80)
        report.append("API SECURITY POSTURE ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"\nBase URL: {session.base_url}")
        report.append(f"Assessment Timestamp: {session.timestamp.isoformat()}")
        report.append(f"\nEndpoints Assessed: {len(session.endpoints_tested)}")
        
        # Security infrastructure summary
        report.append(f"\n--- SECURITY INFRASTRUCTURE ---")
        
        waf_count = sum(1 for e in session.endpoints_tested if e.waf_detected)
        auth_count = sum(1 for e in session.endpoints_tested if e.auth_required)
        edge_count = sum(1 for e in session.endpoints_tested if e.edge_detected)
        
        report.append(f"  ✓ Endpoints with WAF detected: {waf_count}/{len(session.endpoints_tested)}")
        report.append(f"  ✓ Endpoints requiring authentication: {auth_count}/{len(session.endpoints_tested)}")
        report.append(f"  ✓ Endpoints through edge/CDN: {edge_count}/{len(session.endpoints_tested)}")
        
        # Server information
        report.append(f"\n--- SERVER INFORMATION ---")
        servers = set()
        for endpoint in session.endpoints_tested:
            if endpoint.server_info:
                servers.add(endpoint.server_info)
        if servers:
            for server in servers:
                report.append(f"  {server}")
        else:
            report.append("  (Server info not exposed)")
        
        # Cookie security
        report.append(f"\n--- COOKIE SECURITY ---")
        all_cookies = []
        for endpoint in session.endpoints_tested:
            all_cookies.extend(endpoint.set_cookies)
        if all_cookies:
            for cookie in list(set(all_cookies)):
                report.append(f"  {cookie}")
        else:
            report.append("  No cookies set in responses")
        
        # Data exposure assessment
        if session.total_data_points > 0:
            report.append(f"\n--- DATA EXPOSURE ASSESSMENT ---")
            report.append(f"  Total data points found: {session.total_data_points}")
            report.append(f"\n  Sensitivity Breakdown:")
            for sensitivity, count in sorted(session.sensitivity_breakdown.items(), key=lambda x: x[1], reverse=True):
                report.append(f"    {sensitivity.upper()}: {count} data points")
            report.append(f"\n  Data Types Identified:")
            for dtype, count in sorted(session.data_types_found.items(), key=lambda x: x[1], reverse=True):
                report.append(f"    {dtype}: {count}")
        
        # Endpoint-by-endpoint assessment
        report.append(f"\n--- ENDPOINT ASSESSMENT DETAILS ---\n")
        
        # Group by response code
        endpoints_by_code = defaultdict(list)
        for endpoint in session.endpoints_tested:
            endpoints_by_code[endpoint.response_code].append(endpoint)
        
        for code in sorted(endpoints_by_code.keys()):
            endpoints = endpoints_by_code[code]
            status_meaning = {
                200: "OK",
                401: "AUTHENTICATION REQUIRED",
                403: "FORBIDDEN/BLOCKED",
                404: "NOT FOUND",
                500: "SERVER ERROR"
            }.get(code, "OTHER")
            
            report.append(f"\nHTTP {code} ({status_meaning}): {len(endpoints)} endpoint(s)")
            
            for endpoint in endpoints:
                report.append(f"  [{endpoint.method}] {endpoint.path}")
                
                # Only show warnings, not vulnerabilities
                if endpoint.blocked_by_waf:
                    report.append(f"    → WAF blocking detected (403)")
                if endpoint.auth_required:
                    report.append(f"    → Authentication required")
                if endpoint.waf_detected:
                    report.append(f"    → WAF: {endpoint.waf_name}")
                if endpoint.edge_detected:
                    report.append(f"    → Edge/CDN detected")
                if endpoint.error:
                    report.append(f"    → Error: {endpoint.error}")
        
        # Recommendations
        report.append(f"\n--- ASSESSMENT NOTES ---")
        report.append("  This report reflects security infrastructure presence, not exploitable vulnerabilities.")
        if auth_count == len(session.endpoints_tested):
            report.append("  ✓ All tested endpoints require authentication")
        if waf_count > 0:
            report.append(f"  ✓ WAF protection detected on {waf_count} endpoint(s)")
        if edge_count > 0:
            report.append(f"  ✓ Edge/CDN protection active on {edge_count} endpoint(s)")
        
        report.append(f"\n" + "=" * 80)
        return "\n".join(report)
    
    @staticmethod
    def generate_json(session: APITestSession) -> str:
        """Generate JSON report"""
        return json.dumps(session.to_dict(), indent=2, default=str)
    
    @staticmethod
    def export_harvested_data(session: APITestSession) -> List[Dict]:
        """Export all harvested data"""
        export = []
        
        for endpoint in session.endpoints_tested:
            for point in endpoint.data_harvested:
                export.append({
                    'endpoint': endpoint.path,
                    'method': endpoint.method,
                    'timestamp': point.timestamp.isoformat(),
                    'field_name': point.field_name,
                    'field_path': point.path,
                    'value_preview': point.field_value,
                    'data_type': point.data_type,
                    'sensitivity': point.sensitivity,
                })
        
        return export


# ============================================================================
# TEST UTILITIES
# ============================================================================

def quick_test_api(url: str, verbose: bool = True) -> Dict:
    """Quick API test"""
    tester = APITester(url)
    
    if verbose:
        print(f"[*] Testing API: {url}")
        print(f"[*] Discovering endpoints...")
    
    session = tester.traverse_api()
    
    if verbose:
        print(APITestReport.generate_summary(session))
    
    return session.to_dict()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python api_testing_harvester.py <base_url>")
        print("Example: python api_testing_harvester.py http://localhost:8000")
        sys.exit(1)
    
    url = sys.argv[1]
    result = quick_test_api(url)
    
    # Save results
    with open('api_test_results.json', 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n[+] Results saved to api_test_results.json")

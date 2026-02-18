"""
Real-World Pentesting Simulations Module with AI Integration
Provides dynamic scenario-based learning with AI coaching
Now supports pulling data from live websites/targets
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QGroupBox,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton,
    QLabel, QCheckBox, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl
import warnings

from attack_vectors_engine import (
    AttackVectorEngine, AttackPhase, VulnerabilityType
)


class WebTargetScanner:
    """Fetches real data from live websites for simulation"""
    
    def __init__(self):
        self.session = requests.Session()
        # Retry strategy for resilience
        retry = Retry(connect=3, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504))
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def fetch_url(self, url, timeout=10) -> str:
        """Fetch raw content from URL"""
        try:
            warnings.filterwarnings('ignore', message='Unverified HTTPS request')
            response = self.session.get(url, timeout=timeout, verify=False)
            response.raise_for_status()
            return response.text
        except Exception as e:
            return f"Error fetching {url}: {str(e)}"
    
    def analyze_forms(self, url) -> dict:
        """Extract form data from target website"""
        try:
            html = self.fetch_url(url)
            soup = BeautifulSoup(html, 'html.parser')
            
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                
                if form_data['inputs']:
                    forms.append(form_data)
            
            return {'forms': forms, 'url': url}
        except Exception as e:
            return {'error': str(e), 'url': url}
    
    def check_headers(self, url) -> dict:
        """Analyze security headers from target"""
        try:
            response = self.session.head(url, timeout=10, verify=False)
            headers = {k: v for k, v in response.headers.items()}
            
            # Check for security headers
            security_check = {
                'has_csp': 'Content-Security-Policy' in headers,
                'has_hsts': 'Strict-Transport-Security' in headers,
                'has_x_frame': 'X-Frame-Options' in headers,
                'server': headers.get('Server', 'Unknown'),
                'all_headers': headers
            }
            return security_check
        except Exception as e:
            return {'error': str(e)}
    
    def extract_endpoints(self, url) -> dict:
        """Extract API endpoints and internal links"""
        try:
            html = self.fetch_url(url)
            soup = BeautifulSoup(html, 'html.parser')
            
            endpoints = {
                'scripts': [],
                'api_calls': [],
                'links': []
            }
            
            # Extract script sources
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    endpoints['scripts'].append(urljoin(url, src))
            
            # Extract all links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and not href.startswith('#'):
                    endpoints['links'].append(urljoin(url, href))
            
            return endpoints
        except Exception as e:
            return {'error': str(e)}


class RealisticSimulationEngine:
    """Generates realistic responses to pentesting commands"""
    
    def __init__(self):
        self.web_scanner = WebTargetScanner()
        self.live_target_data = {}
    
    SCENARIO_RESPONSES = {
        'ecommerce_login': {
            'curl http': 'HTTP/1.1 200 OK\nServer: Apache/2.4.41\nSet-Cookie: PHPSESSID=abc123def456\nContent-Type: text/html\n\n<html><form method="POST" action="/login.php">\n<input name="username" placeholder="Username">\n<input name="password" type="password" placeholder="Password">\n</form></html>',
            'sqlmap': 'Found SQL injection vulnerability in parameter \'username\'\nDatabases discovered: mysql, information_schema, wordpress\nExtracted users: admin, user1, user2\nPassword hashes: 5f4dcc3b5aa765d61d8327deb882cf99 (admin)',
            'select': 'Successfully extracted user database:\nadmin | 5f4dcc3b5aa765d61d8327deb882cf99 | admin@shop.local',
            'union': 'UNION-based SQL injection confirmed! Database structure revealed.',
            "admin'": 'SQL error revealed! Backend database is MySQL version 5.7.30',
            'default': '200 OK - Request processed'
        },
        'xss_search': {
            '<script>': 'Payload reflected directly in search results page. XSS vulnerability confirmed!',
            'alert': 'XSS Executed! Cookie retrieved: PHPSESSID=0a1b2c3d4e5f6g7h8i9j',
            'fetch': 'JavaScript executed. Admin credentials exfiltrated to attacker server.',
            'document.cookie': 'Current cookies: PHPSESSID=0a1b2c3d4e5f, admin_token=eyJ0eXAi...',
            'default': 'Search completed - 0 results'
        },
        'admin_rce': {
            'upload': 'File upload successful. PHP shell uploaded to /uploads/shell.php',
            'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
            'whoami': 'www-data',
            'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash',
            'nc -e': 'Reverse shell established',
            'default': 'Command executed'
        },
        'ssrf_metadata': {
            'localhost': 'Connected to internal service. AWS metadata endpoint responding.',
            '169.254': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            '127.0.0.1': 'Internal service discovered running on port 8080: Admin Dashboard',
            'file://': 'File protocol blocked by WAF',
            'default': 'Request timeout'
        },
        'jwt_bypass': {
            'jwt': 'Intercepted token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.',
            'decode': 'Header: {"alg":"none"}\nPayload: {"user":"guest","role":"user","iat":1234567890}',
            'forge': 'Admin token forged: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==',
            'none': 'Token with "alg":"none" accepted! Authentication bypassed.',
            'default': 'Token processed'
        },
        'multi_vuln_app': {
            'scan': 'Vulnerabilities found:\n[HIGH] SQL Injection in /api/users\n[HIGH] XSS in search\n[MEDIUM] CSRF token missing\n[HIGH] XXE in XML parser',
            'exploit': 'Chaining: SQL injection for data extraction, XSS for credential stealing',
            'data': 'Successfully exfiltrated 150,000 customer records and source code repository',
            'rce': 'Remote code execution achieved. System shell obtained.',
            'default': 'Exploitation in progress'
        },
        'network_pivot': {
            'nmap': 'Nmap scan results:\n192.168.1.10 - Web Server (SSH:22, HTTP:80, HTTPS:443)\n192.168.1.20 - MySQL (Port 3306 exposed)\n192.168.1.30 - SMB Server (Port 445 writable)',
            'enum': 'Network enumeration complete. 8 live hosts detected.',
            'pivot': 'Lateral movement successful. Compromised database server.',
            'default': 'Network scan executing'
        },
        'privesc_linux': {
            'sudo': 'User may run the following without password:\n(root) /usr/bin/find',
            'suid': '-rwsr-xr-x 1 root root /usr/bin/find',
            'capabilities': 'cap_setuid+ep /usr/bin/python3',
            'find': 'Spawning shell as root via find SUID binary',
            'default': 'Command executed'
        }
    }
    
    def get_response(self, scenario_id: str, command: str, use_live_data=False, target_url=None) -> str:
        """Get realistic response to a penetesting command"""
        
        # If live data requested, fetch from target first
        if use_live_data and target_url:
            return self._get_live_response(command, target_url)
        
        responses = self.SCENARIO_RESPONSES.get(scenario_id, {})
        command_lower = command.lower()
        
        # Exact match
        for key in responses:
            if key != 'default' and key in command_lower:
                return responses[key]
        
        return responses.get('default', 'Command executed successfully')
    
    def _get_live_response(self, command: str, target_url: str) -> str:
        """Generate response based on live target data"""
        command_lower = command.lower()
        
        # curl command - fetch from target
        if 'curl' in command_lower or 'http' in command_lower:
            content = self.web_scanner.fetch_url(target_url)
            if content.startswith('Error'):
                return content
            return f"HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: {len(content)}\n\n{content[:500]}..."
        
        # nmap-like scan
        if 'nmap' in command_lower or 'scan' in command_lower:
            headers = self.web_scanner.check_headers(target_url)
            return f"Security Headers Analysis:\n{json.dumps(headers, indent=2)}"
        
        # Form enumeration
        if 'form' in command_lower or 'fuzzing' in command_lower:
            forms = self.web_scanner.analyze_forms(target_url)
            return f"Forms Discovered:\n{json.dumps(forms, indent=2)}"
        
        # Endpoint extraction
        if 'endpoint' in command_lower or 'api' in command_lower:
            endpoints = self.web_scanner.extract_endpoints(target_url)
            return f"Endpoints Found:\n{json.dumps(endpoints, indent=2)}"
        
        return "Command executed. Use curl, nmap, form, or endpoint commands with live targets."


class AICoachingEngine:
    """Provides intelligent feedback on pentesting approach"""
    
    COACHING_MAP = {
        'ecommerce_login': [
            'Good start! Web application reconnaissance is essential. Next, try to identify and exploit SQL injection vulnerabilities in the login form.',
            'SQL injection detected! Extract the database contents using UNION-based or error-based techniques. Look for user credentials.',
            'Excellent! You\'ve gained access. Now escalate privileges - look for admin accounts or functionality.',
        ],
        'xss_search': [
            'Good reconnaissance. You\'ve identified the search input as a potential reflection point. Test for reflected XSS.',
            'Perfect XSS confirmation! Now craft a payload to steal session cookies using fetch or fetch with withCredentials.',
            'Great! Session token captured. Use this to impersonate the admin user and access protected functionality.',
        ],
        'admin_rce': [
            'Smart approach! File upload is a common RCE vector. Try uploading a PHP shell to get command execution.',
            'Excellent! You\'ve achieved RCE as www-data. Now establish a reverse shell for persistent access.',
            'Good shell access. Next, enumerate the system for privilege escalation opportunities.',
        ],
        'ssrf_metadata': [
            'Solid reconnaissance! SSRF vulnerabilities can access internal services. Try targeting the AWS metadata endpoint.',
            'Great SSRF exploitation! You\'ve extracted AWS credentials. Use these to access internal resources or S3 buckets.',
            'Excellent credential extraction! Now pivot to other internal services using these credentials.',
        ],
        'jwt_bypass': [
            'Good token analysis! JWT tokens with "alg":"none" are vulnerable to signature bypass.',
            'Smart! You\'ve forged an admin token. Now use it to access protected API endpoints.',
            'Perfect exploitation! You have full admin access. Document all findings in a comprehensive report.',
        ],
        'multi_vuln_app': [
            'Excellent vulnerability discovery! You\'ve found multiple issues. Now chain them together for greater impact.',
            'Smart exploitation! Combining SQL injection with XSS creates a powerful attack chain.',
            'Great work! You\'ve achieved data exfiltration and RCE. This demonstrates the severity of chained vulnerabilities.',
        ],
        'network_pivot': [
            'Good enumeration! You\'ve discovered internal network topology. Now identify high-value targets.',
            'Smart lateral movement! Database compromise gives you access to sensitive data.',
            'Excellent pivot! You\'re successfully moving through the internal network.',
        ],
        'privesc_linux': [
            'Good enumeration! SUID binaries are a common privilege escalation vector.',
            'Excellent discovery! The /usr/bin/find SUID binary can be exploited for privilege escalation.',
            'Perfect! You\'re now running as root. Establish persistence and document findings.',
        ]
    }
    
    @staticmethod
    def get_coaching(scenario_id: str, attempt_number: int = 0) -> str:
        """Get coaching feedback based on scenario and progress"""
        coaching_list = AICoachingEngine.COACHING_MAP.get(scenario_id, ['Keep testing!'])
        
        if attempt_number >= len(coaching_list):
            return 'Excellent work! You\'ve successfully completed the scenario. Can you think of defensive measures?'
        
        return coaching_list[min(attempt_number, len(coaching_list) - 1)]


def create_attack_vectors_tab() -> QWidget:
    """Create attack vectors and threat scenarios reference tab"""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    
    # Initialize engine
    engine = AttackVectorEngine()
    
    # Header
    header = QGroupBox("🎯 Attack Vectors & Threat Scenarios")
    header_layout = QVBoxLayout(header)
    header_layout.addWidget(QLabel("Comprehensive catalog of attack vectors and threat scenarios mapped to MITRE ATT&CK"))
    layout.addWidget(header)
    
    # Tabs
    tabs = QTabWidget()
    
    # TAB 1: Threat Scenarios
    scenarios_tab = QWidget()
    scenarios_layout = QVBoxLayout(scenarios_tab)
    
    scenarios_list = QListWidget()
    for scenario in engine.scenarios.values():
        item = QListWidgetItem(f"[{scenario.severity}] {scenario.name}")
        item.setData(Qt.ItemDataRole.UserRole, scenario.scenario_id)
        
        # Color code by severity
        if scenario.severity == 'Critical':
            item.setBackground(QColor(255, 100, 100))
        elif scenario.severity == 'High':
            item.setBackground(QColor(255, 165, 0))
        
        scenarios_list.addItem(item)
    
    scenarios_layout.addWidget(QLabel("Threat Scenarios:"))
    scenarios_layout.addWidget(scenarios_list)
    
    # Scenario details
    scenario_details = QTextEdit()
    scenario_details.setReadOnly(True)
    scenarios_layout.addWidget(QLabel("Scenario Details:"))
    scenarios_layout.addWidget(scenario_details)
    
    def show_scenario_details():
        item = scenarios_list.currentItem()
        if not item:
            return
        
        scenario_id = item.data(Qt.ItemDataRole.UserRole)
        scenario = engine.get_scenario(scenario_id)
        
        details = f"""
╔═══════════════════════════════════════════════╗
║  THREAT SCENARIO: {scenario.name}
╚═══════════════════════════════════════════════╝

📋 Description:
{scenario.description}

🎯 Target Type: {scenario.target_type}
⚠️  Severity: {scenario.severity}
⏱️  Estimated Time: {scenario.estimated_time} minutes
📊 Difficulty: {scenario.difficulty}

🔗 Attack Vectors Used:
"""
        for vid in scenario.attack_vectors:
            vector = engine.get_vector(vid)
            if vector:
                details += f"  • {vector.name} ({vector.difficulty})\n"
        
        details += "\n📈 Attack Chain:\n"
        for step, (phase, vector_id) in enumerate(scenario.attack_chain, 1):
            vector = engine.get_vector(vector_id)
            details += f"  {step}. [{phase}] {vector.name if vector else 'Unknown'}\n"
        
        details += "\n🎓 Learning Objectives:\n"
        for obj in scenario.learning_objectives:
            details += f"  • {obj}\n"
        
        details += "\n✅ Success Criteria:\n"
        for criteria in scenario.success_criteria:
            details += f"  ✓ {criteria}\n"
        
        scenario_details.setText(details)
    
    scenarios_list.itemSelectionChanged.connect(show_scenario_details)
    tabs.addTab(scenarios_tab, "🎭 Threat Scenarios")
    
    # TAB 2: Attack Vectors
    vectors_tab = QWidget()
    vectors_layout = QVBoxLayout(vectors_tab)
    
    # Filter by type
    filter_layout = QHBoxLayout()
    filter_layout.addWidget(QLabel("Filter by:"))
    
    vuln_filter = QComboBox()
    vuln_filter.addItem("All Vulnerabilities", None)
    for vuln_type in VulnerabilityType:
        vuln_filter.addItem(vuln_type.value, vuln_type)
    
    phase_filter = QComboBox()
    phase_filter.addItem("All Phases", None)
    for phase in AttackPhase:
        phase_filter.addItem(phase.value, phase)
    
    filter_layout.addWidget(QLabel("Vulnerability:"))
    filter_layout.addWidget(vuln_filter)
    filter_layout.addWidget(QLabel("Phase:"))
    filter_layout.addWidget(phase_filter)
    vectors_layout.addLayout(filter_layout)
    
    vectors_list = QListWidget()
    for vector in engine.vectors.values():
        item = QListWidgetItem(f"[{vector.difficulty}] {vector.name}")
        item.setData(Qt.ItemDataRole.UserRole, vector.vector_id)
        vectors_list.addItem(item)
    
    vectors_layout.addWidget(QLabel("Attack Vectors:"))
    vectors_layout.addWidget(vectors_list)
    
    # Vector details
    vector_details = QTextEdit()
    vector_details.setReadOnly(True)
    vectors_layout.addWidget(QLabel("Vector Details:"))
    vectors_layout.addWidget(vector_details)
    
    def show_vector_details():
        item = vectors_list.currentItem()
        if not item:
            return
        
        vector_id = item.data(Qt.ItemDataRole.UserRole)
        vector = engine.get_vector(vector_id)
        
        details = f"""
╔═══════════════════════════════════════════════╗
║  ATTACK VECTOR: {vector.name}
╚═══════════════════════════════════════════════╝

📖 Description:
{vector.description}

🔍 Vulnerability Type: {vector.vuln_type.value}
📍 Attack Phase: {vector.phase.value}
📊 Difficulty: {vector.difficulty}

🛠️ Tools:
{', '.join(vector.tools)}

⚙️ Payloads:
"""
        for payload in vector.payloads:
            details += f"  • {payload}\n"
        
        details += f"\n📚 CVE References:\n"
        for cve in vector.cve_refs:
            details += f"  • {cve}\n"
        
        details += f"\n🔴 Detection Signals:\n"
        for signal in vector.detection_signals:
            details += f"  • {signal}\n"
        
        details += f"\n✅ Mitigation:\n"
        for mitigation in vector.mitigation:
            details += f"  • {mitigation}\n"
        
        details += f"\n🔗 References:\n"
        for ref in vector.references:
            details += f"  • {ref}\n"
        
        # Show related scenarios
        related = engine.get_related_scenarios(vector_id)
        if related:
            details += f"\n📋 Used in Scenarios:\n"
            for scenario in related:
                details += f"  • {scenario.name}\n"
        
        vector_details.setText(details)
    
    def apply_filters():
        vuln_type = vuln_filter.currentData()
        phase = phase_filter.currentData()
        
        vectors_list.clear()
        for vector in engine.vectors.values():
            if vuln_type and vector.vuln_type != vuln_type:
                continue
            if phase and vector.phase != phase:
                continue
            
            item = QListWidgetItem(f"[{vector.difficulty}] {vector.name}")
            item.setData(Qt.ItemDataRole.UserRole, vector.vector_id)
            vectors_list.addItem(item)
    
    vuln_filter.currentIndexChanged.connect(apply_filters)
    phase_filter.currentIndexChanged.connect(apply_filters)
    vectors_list.itemSelectionChanged.connect(show_vector_details)
    tabs.addTab(vectors_tab, "🗡️ Attack Vectors")
    
    # TAB 3: Learning Paths
    learning_tab = QWidget()
    learning_layout = QVBoxLayout(learning_tab)
    
    difficulty_filter = QComboBox()
    for difficulty in ['Easy', 'Medium', 'Hard', 'Expert']:
        difficulty_filter.addItem(difficulty, difficulty)
    
    learning_layout.addWidget(QLabel("Select Learning Path Difficulty:"))
    learning_layout.addWidget(difficulty_filter)
    
    learning_path_text = QTextEdit()
    learning_path_text.setReadOnly(True)
    learning_layout.addWidget(learning_path_text)
    
    def show_learning_path():
        difficulty = difficulty_filter.currentData()
        path = engine.get_learning_path(difficulty)
        
        text = f"🎓 Learning Path: {difficulty} Level\n\n"
        for item in path:
            scenario = item['scenario']
            text += f"""
═══════════════════════════════════════════════
Step {item['progression']}: {scenario['name']}
═══════════════════════════════════════════════
{scenario['description']}

Time: {scenario['estimated_time']} min | Vectors: {len(item['vectors'])}

Attack Vectors:
"""
            for vector in item['vectors']:
                text += f"  • {vector['name']} ({vector['difficulty']})\n"
            text += "\n"
        
        learning_path_text.setText(text)
    
    difficulty_filter.currentIndexChanged.connect(show_learning_path)
    learning_layout.addStretch()
    tabs.addTab(learning_tab, "🎓 Learning Paths")
    
    layout.addWidget(tabs)
    
    return widget


def create_realistic_simulations_tab() -> QWidget:
    """Create the realistic pentesting simulations tab"""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    
    # Header
    header = QGroupBox("🎯 Real-World Pentesting Simulations")
    header_layout = QVBoxLayout(header)
    header_layout.addWidget(QLabel("Practice real-world pentesting with AI coaching. Supports both simulated and live target data."))
    layout.addWidget(header)
    
    # Target Configuration
    target_group = QGroupBox("🎯 Target Configuration")
    target_layout = QVBoxLayout(target_group)
    
    target_url_input = QLineEdit()
    target_url_input.setPlaceholderText("Enter target URL (e.g., http://example.com) - optional for live scanning")
    target_layout.addWidget(QLabel("Live Target URL:"))
    target_layout.addWidget(target_url_input)
    
    use_live_checkbox = QCheckBox("Use Live Target Data (fetch real data from URL)")
    use_live_checkbox.setChecked(False)
    target_layout.addWidget(use_live_checkbox)
    
    layout.addWidget(target_group)
    
    # Main splitter
    main_splitter = QSplitter(Qt.Orientation.Vertical)
    
    # SETUP SECTION
    setup_group = QGroupBox("📋 Scenario Selection")
    setup_layout = QVBoxLayout(setup_group)
    
    scenarios_list = QListWidget()
    scenarios_data = [
        ("🔓 E-Commerce Login Bypass", "ecommerce_login", "Easy", "SQL injection in login form"),
        ("🕸️ Reflected XSS in Search", "xss_search", "Easy", "Cookie theft via JavaScript"),
        ("💉 Admin Panel RCE", "admin_rce", "Medium", "File upload to remote code execution"),
        ("🎭 AWS Metadata SSRF", "ssrf_metadata", "Medium", "Extract AWS credentials"),
        ("🔐 JWT Authentication Bypass", "jwt_bypass", "Medium", "Forge authentication tokens"),
        ("🏗️ Multi-Vulnerability App", "multi_vuln_app", "Hard", "Chain multiple exploits"),
        ("📡 Network Pivoting", "network_pivot", "Hard", "Lateral movement and escalation"),
        ("👤 Privilege Escalation", "privesc_linux", "Hard", "Linux privilege escalation"),
    ]
    
    scenarios_map = {}
    for display_name, scenario_id, difficulty, description in scenarios_data:
        item = QListWidgetItem(display_name)
        item.setData(Qt.ItemDataRole.UserRole, scenario_id)
        scenarios_list.addItem(item)
        scenarios_map[scenario_id] = {
            'name': display_name,
            'difficulty': difficulty,
            'description': description
        }
    
    setup_layout.addWidget(scenarios_list)
    main_splitter.addWidget(setup_group)
    
    # CONSOLE SECTION
    console_group = QGroupBox("🖥️ Pentesting Console")
    console_layout = QVBoxLayout(console_group)
    
    # Status
    status_layout = QHBoxLayout()
    status_label = QLabel("🔴 Ready")
    status_layout.addWidget(status_label)
    status_layout.addStretch()
    console_layout.addLayout(status_layout)
    
    # Console output
    console_output = QTextEdit()
    console_output.setReadOnly(True)
    console_output.setFont(QFont("Consolas", 9))
    console_layout.addWidget(console_output)
    
    # Command input
    input_layout = QHBoxLayout()
    command_input = QLineEdit()
    command_input.setPlaceholderText("Enter pentesting command (sqlmap, curl, nmap, etc.)...")
    execute_btn = QPushButton("▶ Execute")
    input_layout.addWidget(command_input)
    input_layout.addWidget(execute_btn)
    console_layout.addLayout(input_layout)
    
    main_splitter.addWidget(console_group)
    
    # AI COACHING SECTION
    coaching_group = QGroupBox("🤖 AI Coaching & Analysis")
    coaching_layout = QVBoxLayout(coaching_group)
    
    coaching_text = QTextEdit()
    coaching_text.setReadOnly(True)
    coaching_text.setFont(QFont("Segoe UI", 10))
    coaching_layout.addWidget(coaching_text)
    
    main_splitter.addWidget(coaching_group)
    
    main_splitter.setStretchFactor(0, 0)
    main_splitter.setStretchFactor(1, 2)
    main_splitter.setStretchFactor(2, 1)
    
    layout.addWidget(main_splitter)
    
    # Initialize simulation engine
    sim_engine = RealisticSimulationEngine()
    
    # Connect signals
    def on_execute():
        command = command_input.text().strip()
        if not command:
            return
        
        current_item = scenarios_list.currentItem()
        scenario_id = current_item.data(Qt.ItemDataRole.UserRole) if current_item else None
        
        # Check if using live data
        use_live = use_live_checkbox.isChecked()
        target_url = target_url_input.text().strip() if use_live else None
        
        if use_live and not target_url:
            coaching_text.setText("❌ Please enter a target URL to use live data mode")
            return
        
        if not use_live and not current_item:
            coaching_text.setText("Please select a scenario first")
            return
        
        # Get response
        status_label.setText("⏳ Executing...")
        
        def run_in_thread():
            """Run command in background thread"""
            try:
                response = sim_engine.get_response(scenario_id, command, use_live_data=use_live, target_url=target_url)
                
                # Get AI coaching
                if scenario_id:
                    coaching = AICoachingEngine.get_coaching(scenario_id)
                else:
                    coaching = f"✓ Live target data fetched successfully"
                
                # Schedule UI updates on main thread using QTimer
                def update_ui():
                    try:
                        current = console_output.toPlainText()
                        console_output.setText(current + f"\n$ {command}\n{response}\n")
                        coaching_text.setText(f"🤖 AI Analysis:\n\n{coaching}")
                        status_label.setText("🟢 Command Executed")
                    except Exception as ui_err:
                        status_label.setText(f"🔴 UI Error: {str(ui_err)}")
                
                QTimer.singleShot(0, update_ui)
            except Exception as e:
                # Schedule error update on main thread
                def update_error():
                    try:
                        current = console_output.toPlainText()
                        console_output.setText(current + f"\n$ {command}\n❌ Error: {str(e)}\n")
                        status_label.setText("🔴 Error")
                    except:
                        pass
                
                QTimer.singleShot(0, update_error)
        
        # Run in background thread
        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()
        
        command_input.clear()
    
    execute_btn.clicked.connect(on_execute)
    command_input.returnPressed.connect(on_execute)
    
    def on_scenario_selected():
        if scenarios_list.currentItem():
            console_output.clear()
            coaching_text.clear()
            status_label.setText("🔴 Ready")
            scenario_id = scenarios_list.currentItem().data(Qt.ItemDataRole.UserRole)
            console_output.setText(f"Scenario: {scenarios_map[scenario_id]['description']}\n\nType commands to begin...")
    
    scenarios_list.itemSelectionChanged.connect(on_scenario_selected)
    
    return widget

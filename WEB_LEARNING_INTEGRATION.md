# Web Learning & AI Knowledge Enhancement

## Overview

HadesAI now has **intelligent web learning capabilities** that enable the AI system to:
- **Learn from webpages** it scans and seeks
- **Extract security intelligence** (CVEs, exploits, techniques, vulnerabilities)
- **Enhance LLM responses** with real-world security data
- **Build a growing knowledge base** from security research
- **Provide informed answers** grounded in actual vulnerability data

## Architecture

### Core Components

1. **WebKnowledgeLearner** (`web_knowledge_learner.py`)
   - Extracts CVEs, CWEs, exploits, techniques, and vulnerability patterns
   - Stores learned information in SQLite database
   - Provides knowledge lookup for queries

2. **AIKnowledgeEnhancer** (`ai_knowledge_enhancer.py`)
   - Integrates learned knowledge into AI prompts
   - Enhances LLM responses with security context
   - Processes scan results for learning
   - Provides learning analytics and reporting

3. **ChatAIKnowledgeMiddleware** (in `ai_knowledge_enhancer.py`)
   - Integrates with chat interactions
   - Processes user messages with knowledge context
   - Enhances AI responses automatically

## Database Schema

### Learned Knowledge Tables

```sql
-- Web sources that have been scanned/processed
web_sources (source_id, url, domain, content_hash, title, accessed_date)

-- Learned CVE information
learned_cves (cve_id, severity, description, context, source_urls, learned_date)

-- Learned exploits from webpages
web_learned_exploits (exploit_id, exploit_type, code_snippet, source_url, learned_date)

-- Learned pentesting techniques
learned_techniques (technique_id, category, name, description, source_urls, learned_date)

-- Learned vulnerability patterns
web_learned_patterns (pattern_id, pattern_type, signature, context, source_url, learned_date, confidence)

-- Learning analytics
learning_analytics (analytics_id, metric_type, value, timestamp, description)
```

## Usage Examples

### 1. Basic Learning from Webpage Content

```python
from web_knowledge_learner import WebKnowledgeLearner

learner = WebKnowledgeLearner()

# Learn from security blog post
webpage_content = """
CVE-2024-1234 is a critical SQL injection vulnerability...
The exploit involves sending a crafted query to bypass authentication...
"""

result = learner.learn_from_content(
    url="https://security-blog.com/article",
    content=webpage_content,
    metadata={'title': 'CVE-2024-1234 Analysis'}
)

print(result)
# {
#   'cves': ['CVE-2024-1234'],
#   'exploits': ['SQL_INJECTION'],
#   'techniques': ['enumeration', 'exploitation'],
#   'patterns': ['SQL_INJECTION'],
#   'total_items_learned': 4
# }

learner.close()
```

### 2. Enhance AI Responses with Learned Knowledge

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# User asks a security question
user_query = "What are common SQL injection techniques?"

# Enhance prompt with learned knowledge
enhanced = enhancer.enhance_prompt(user_query, system_prompt="You are a security expert")

# Use enhanced prompt with any LLM
ai_response = call_your_llm(
    system=enhanced['system'],
    user=enhanced['user']
)

# Further enhance the response
final_response = enhancer.get_ai_response_with_knowledge(user_query, ai_response)

print(final_response)
# Response now includes learned CVE data, exploit techniques, etc.

enhancer.close()
```

### 3. Learn from Scan Results

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Results from seek_tab, vulnerability scanner, etc.
scan_results = {
    'vulnerabilities': [
        {'type': 'SQL Injection', 'cve': 'CVE-2024-1234', 'severity': 'CRITICAL'},
        {'type': 'XSS', 'cve': 'CVE-2024-5678', 'severity': 'HIGH'}
    ],
    'exploits': [
        {'type': 'SQLi Payload', 'code': "' OR '1'='1"}
    ],
    'raw_content': 'Full vulnerability report...'
}

learning_summary = enhancer.learn_from_scan_results(scan_results, source_url="https://target.com")

print(learning_summary)
# {
#   'items_processed': 3,
#   'items_learned': 7,
#   'timestamp': '2024-01-15T...'
# }

enhancer.close()
```

### 4. Integrate with Chat Interface

```python
from ai_knowledge_enhancer import ChatAIKnowledgeMiddleware

# In your chat handler
middleware = ChatAIKnowledgeMiddleware()

# Process user message
processed = middleware.process_user_message(
    user_message="How do I test for CSRF vulnerabilities?",
    system_prompt="You are a security expert"
)

# enhanced_system contains learned CSRF knowledge
ai_response = call_your_llm(processed['enhanced_system'], processed['enhanced_user'])

# Enhance the response
final = middleware.process_llm_response(
    user_query="How do I test for CSRF vulnerabilities?",
    llm_response=ai_response
)

print(final['enhanced_response'])  # Response with CSRF vulnerability patterns added

# Optional: Learn from successful interaction
middleware.learn_from_interaction(
    user_query="How do I test for CSRF vulnerabilities?",
    ai_response=final['enhanced_response']
)

middleware.close()
```

## Integration with Existing Components

### With Seek Tab (Exploit Seeking)

```python
from exploit_seek_tab import exploit_seeker_thread
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# After seek_tab finds exploits
exploits = exploit_seeker_thread(target)

# Learn from discovered exploits
for exploit in exploits:
    enhancer.learn_from_scan_results({
        'exploits': [exploit],
        'raw_content': exploit['description']
    }, source_url=exploit['source_url'])
```

### With Vulnerability Scanner

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# After scanner finds vulnerabilities
scanner_results = run_vulnerability_scan(target)

# Learn from findings
learning = enhancer.learn_from_scan_results(
    scanner_results,
    source_url=f"https://{target}/scan-results"
)

print(f"Learned {learning['items_learned']} new pieces of information")
```

### With Autonomous Coding Agent

```python
from autonomouscoding import AutonomousCodingAgent
from ai_knowledge_enhancer import ChatAIKnowledgeMiddleware

middleware = ChatAIKnowledgeMiddleware()

# Wrap agent prompts with knowledge enhancement
def enhanced_agent_query(query):
    processed = middleware.process_user_message(query)
    # Use processed['enhanced_system'] and processed['enhanced_user']
    # ... agent code ...
```

## Knowledge Extraction Capabilities

### CVE Extraction
- Identifies CVE-XXXX-XXXX patterns
- Extracts severity levels and CVSS scores
- Captures contextual information
- Stores source URLs for reference

### Exploit Detection
- Identifies exploit-related keywords (payload, shellcode, PoC, etc.)
- Captures code snippets and technical details
- Categorizes by exploit type (SQL injection, RCE, etc.)
- Preserves source attribution

### Technique Recognition
- Enumeration and reconnaissance techniques
- Exploitation methodologies
- Privilege escalation approaches
- Persistence mechanisms
- Lateral movement strategies
- Data exfiltration methods
- Defense evasion tactics

### Vulnerability Pattern Identification
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
- Authentication Bypass
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- XML External Entity (XXE)
- Insecure Deserialization
- Broken Access Control

## Analytics & Reporting

### Get Learning Statistics

```python
from web_knowledge_learner import WebKnowledgeStore

store = WebKnowledgeStore()
stats = store.get_learning_stats()

print(stats)
# {
#   'cves_learned': 42,
#   'exploits_learned': 158,
#   'techniques_learned': 73,
#   'patterns_learned': 94,
#   'sources_processed': 12
# }

store.close()
```

### Generate Learning Report

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()
report = enhancer.create_learning_report()
print(report)

enhancer.close()
```

### Export Knowledge Base

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Export as JSON
json_export = enhancer.export_learned_knowledge('json')
with open('learned_knowledge.json', 'w') as f:
    f.write(json_export)

enhancer.close()
```

## Configuration

### Adjust Extraction Sensitivity

```python
from web_knowledge_learner import WebContentExtractor

extractor = WebContentExtractor()

# The regex patterns can be customized for specific needs
# Default patterns are comprehensive for standard security research

# Custom confidence thresholds
severity = extractor._extract_severity(content)
```

### Database Location

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

# Use custom database location
enhancer = AIKnowledgeEnhancer(db_path="/path/to/custom/knowledge.db")
```

## Performance Considerations

1. **Initial Learning**: First scans will extract more data as knowledge base is empty
2. **Duplicate Detection**: Content hashes prevent redundant learning
3. **Query Performance**: Learned data is indexed for fast retrieval
4. **Database Size**: Grows with amount of scanned content, manageable at thousands of items
5. **Memory**: Minimal overhead, efficient SQL queries

## Security Notes

- Learned data is stored locally in SQLite
- No external API calls for knowledge storage
- Source URLs are preserved for attribution
- Knowledge base remains private to your instance
- Can be encrypted or stored securely as needed

## Troubleshooting

### Knowledge Not Being Extracted

```python
from web_knowledge_learner import WebKnowledgeLearner
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

learner = WebKnowledgeLearner()
result = learner.learn_from_content(url, content)
# Check logs for extraction details
```

### Queries Not Finding Learned Knowledge

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Check what's in the knowledge base
stats = enhancer.learner.store.get_learning_stats()
print(stats)

# Verify the query terms match stored data
context = enhancer.learner.get_knowledge_context_for_query("SQL injection")
print(context)
```

## Best Practices

1. **Regular Scanning**: Continuously scan security research sites
2. **Diverse Sources**: Learn from multiple security publications
3. **Real-World Testing**: Run scans on authorized targets to learn real vulnerabilities
4. **Knowledge Hygiene**: Periodically review and validate learned information
5. **Backup Knowledge**: Export knowledge base for backup/sharing
6. **Integrate Early**: Add learning to your security workflows immediately

## Future Enhancements

- Machine learning classification of vulnerability patterns
- Automatic confidence scoring based on source authority
- Integration with threat intelligence feeds
- Cross-correlation of related CVEs and exploits
- Predictive analysis of emerging vulnerabilities
- Knowledge sharing between instances

## API Reference

### WebKnowledgeLearner

```python
class WebKnowledgeLearner:
    def learn_from_content(url: str, content: str, metadata: Dict) -> Dict
    def get_knowledge_context_for_query(query: str) -> str
    def close()
```

### AIKnowledgeEnhancer

```python
class AIKnowledgeEnhancer:
    def enhance_prompt(user_query: str, system_prompt: str) -> Dict
    def learn_from_scan_results(scan_results: Dict, source_url: str) -> Dict
    def get_ai_response_with_knowledge(user_query: str, ai_response: str) -> str
    def create_learning_report() -> str
    def export_learned_knowledge(output_format: str) -> str
    def close()
```

### ChatAIKnowledgeMiddleware

```python
class ChatAIKnowledgeMiddleware:
    def process_user_message(user_message: str, system_prompt: str) -> Dict
    def process_llm_response(user_query: str, llm_response: str) -> Dict
    def learn_from_interaction(user_query: str, ai_response: str, metadata: Dict) -> bool
    def close()
```

---

**Start learning from security research today to make your AI more intelligent!**

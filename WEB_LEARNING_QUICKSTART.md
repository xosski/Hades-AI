# Web Learning & AI Knowledge Enhancement - Quick Start

## 30-Second Setup

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

# Initialize
enhancer = AIKnowledgeEnhancer()

# Learn from webpage
result = enhancer.learner.learn_from_content(
    url="https://security-blog.com/cve-article",
    content="CVE-2024-1234 is a critical SQL injection vulnerability..."
)
print(f"Learned: {result['total_items_learned']} items")

# Enhance your AI prompts
enhanced = enhancer.enhance_prompt("How do I test for SQL injection?")
# Use enhanced['system'] and enhanced['user'] with your LLM

enhancer.close()
```

## Key Features at a Glance

| Feature | What It Does | Result |
|---------|-------------|--------|
| **CVE Learning** | Extracts CVE-XXXX-XXXX patterns from content | Real CVE data in responses |
| **Exploit Extraction** | Finds exploit code, payloads, PoCs | Practical exploitation examples |
| **Technique Recognition** | Identifies pentesting methodologies | Methodologically sound advice |
| **Pattern Matching** | Detects SQL injection, XSS, CSRF, etc. | Specific vulnerability insights |
| **Prompt Enhancement** | Injects learned knowledge into AI prompts | Smarter, more informed AI |
| **Scan Integration** | Learns from vulnerability scanner results | Continuous knowledge growth |

## 3-Minute Implementation

### Step 1: Enable Learning in Seek Tab

```python
# In exploit_seek_tab.py, after finding exploits:

from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# After you get seek results
for result in seek_results:
    enhancer.learn_from_scan_results({
        'exploits': [result],
        'raw_content': result.get('description', '')
    }, source_url=result.get('source', 'seek_tab'))
```

### Step 2: Enhance Chat AI Responses

```python
# In your chat handler:

from ai_knowledge_enhancer import ChatAIKnowledgeMiddleware

middleware = ChatAIKnowledgeMiddleware()

# Process user message
processed = middleware.process_user_message(user_query, system_prompt)

# Call your LLM with enhanced prompts
ai_response = your_llm(processed['enhanced_system'], processed['enhanced_user'])

# Enhance the response
final_response = middleware.process_llm_response(user_query, ai_response)

print(final_response['enhanced_response'])  # Now includes learned knowledge
```

### Step 3: Learn from Scanner Results

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# After running vulnerability scan
scanner_output = {
    'vulnerabilities': [
        {'type': 'SQL Injection', 'cve': 'CVE-2024-1234', 'endpoint': '/api/search'}
    ],
    'raw_content': 'Full scan report...'
}

learning = enhancer.learn_from_scan_results(
    scanner_output,
    source_url="https://target.com/scan"
)

print(f"✅ Learned {learning['items_learned']} new security insights")
```

## What Gets Learned?

### From Security Blog Posts
- CVE identifiers and severity levels
- Exploit code snippets
- Vulnerability descriptions
- Mitigation techniques

### From Vulnerability Scanners
- Discovered CVEs on target systems
- Exploitation payloads
- Security pattern matches
- Risk assessments

### From Penetration Tests
- Successful exploitation techniques
- Network reconnaissance methods
- Privilege escalation approaches
- Persistence mechanisms

## Using Learned Knowledge

### Single Query
```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Get knowledge for a specific topic
context = enhancer.learner.get_knowledge_context_for_query("SQL injection")
print(context)  # Lists learned CVEs, exploits, and techniques

# Example output:
# **Learned CVEs:**
# - CVE-2024-1234 (Severity: CRITICAL)
# 
# **Learned Exploits:**
# - SQL_INJECTION: ' OR '1'='1...
```

### Chat Integration
```python
from ai_knowledge_enhancer import ChatAIKnowledgeMiddleware

middleware = ChatAIKnowledgeMiddleware()

# Every chat message is automatically enhanced
# The AI now has access to learned security knowledge
```

### Analytics
```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# See what you've learned
report = enhancer.create_learning_report()
print(report)

# Sample output:
# Total CVEs Learned: 42
# Total Exploits Learned: 158
# Total Techniques Learned: 73
# Total Patterns Learned: 94
# Web Sources Processed: 12
```

## Example: Complete Workflow

```python
#!/usr/bin/env python3
from ai_knowledge_enhancer import AIKnowledgeEnhancer

def main():
    enhancer = AIKnowledgeEnhancer()
    
    # Step 1: Learn from security research
    print("[*] Learning from security research...")
    cve_article = """
    CVE-2024-45678 is a critical authentication bypass in WebApp v2.1
    Attackers can bypass login by sending Authorization header injection
    The vulnerability affects all versions before 2.1.5
    """
    
    result = enhancer.learner.learn_from_content(
        url="https://securityblog.com/cve-2024-45678",
        content=cve_article
    )
    print(f"    ✓ Learned: {result}")
    
    # Step 2: Enhance AI response
    print("\n[*] Enhancing AI response...")
    user_question = "What authentication vulnerabilities should I test for?"
    
    enhanced = enhancer.enhance_prompt(user_question)
    print(f"    ✓ Enhanced with context: {enhanced['has_context']}")
    
    # Step 3: Get knowledge context
    print("\n[*] Retrieved learned knowledge:")
    context = enhancer.learner.get_knowledge_context_for_query(user_question)
    print(context[:300] + "...")
    
    # Step 4: Report
    print("\n[*] Learning Statistics:")
    stats = enhancer.learner.store.get_learning_stats()
    for key, value in stats.items():
        print(f"    - {key}: {value}")
    
    enhancer.close()
    print("\n✅ Complete!")

if __name__ == "__main__":
    main()
```

## Common Use Cases

### 1. Automated Security Training
```python
# Continuously learn from security feeds
import requests
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Scan daily security blogs
for url in security_blog_urls:
    response = requests.get(url)
    enhancer.learner.learn_from_content(url, response.text)
```

### 2. Target-Specific Knowledge
```python
# Learn about specific target's vulnerabilities
results = run_scanner(target_url)
enhancer.learn_from_scan_results(results, source_url=target_url)

# AI now knows about this target's specific issues
context = enhancer.learner.get_knowledge_context_for_query(target_url)
```

### 3. Incident Response
```python
# Learn from incident findings
incident_report = load_incident_report()
enhancer.learn_from_scan_results(
    {'raw_content': incident_report},
    source_url="incident:INC-001"
)

# AI can reference incident patterns in future analyses
```

### 4. Compliance & Documentation
```python
# Export learned knowledge for compliance
knowledge_export = enhancer.export_learned_knowledge('json')
with open('security_knowledge_audit.json', 'w') as f:
    f.write(knowledge_export)
```

## Monitoring Learning

```python
from ai_knowledge_enhancer import AIKnowledgeEnhancer

enhancer = AIKnowledgeEnhancer()

# Track learning progress
initial_stats = enhancer.learner.store.get_learning_stats()

# ... do some scans ...

final_stats = enhancer.learner.store.get_learning_stats()

print(f"New CVEs: {final_stats['cves_learned'] - initial_stats['cves_learned']}")
print(f"New Exploits: {final_stats['exploits_learned'] - initial_stats['exploits_learned']}")
print(f"New Techniques: {final_stats['techniques_learned'] - initial_stats['techniques_learned']}")
```

## Troubleshooting

### Nothing is being learned?
1. Check that content contains CVEs (CVE-XXXX-XXXX pattern)
2. Verify vulnerability keywords are present (SQL injection, XSS, etc.)
3. Enable logging to see what's extracted:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### AI responses not using learned knowledge?
1. Make sure `enhance_prompt()` is being called before LLM
2. Check that knowledge base has data:
```python
stats = enhancer.learner.store.get_learning_stats()
assert stats['cves_learned'] > 0
```
3. Verify query terms match learned data

### Database errors?
1. Check database file permissions
2. Ensure database is not locked by another process
3. Try backing up and recreating:
```python
import shutil
shutil.copy('hades_knowledge.db', 'hades_knowledge.db.backup')
# Delete and reinitialize
```

## Performance Tips

1. **Batch Learning**: Process multiple items before querying
2. **Query Specificity**: Use specific keywords for faster lookups
3. **Database Maintenance**: Periodically export and archive old data
4. **Learning Frequency**: Learn during off-peak hours for active targets

## Next Steps

1. ✅ Integrate learning with your scanner
2. ✅ Enable AI response enhancement in chat
3. ✅ Set up automated daily security research learning
4. ✅ Monitor learning analytics
5. ✅ Export knowledge base for compliance
6. ✅ Share knowledge base with team

---

**Your AI is now learning and getting smarter with every scan! 🚀**

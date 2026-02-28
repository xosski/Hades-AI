# Tome AI Integration - Quick Start

## What This Does

The Exploit Tome is now **fluid and connected to the AI**. The AI can:

✅ **Access the Tome** - Read all stored exploits and learn from them
✅ **Analyze Patterns** - Understand what works, what doesn't
✅ **Craft New Exploits** - Generate novel exploits based on knowledge
✅ **Combine Exploits** - Create multi-stage attacks
✅ **Get Smart Recommendations** - Suggest best exploits for targets
✅ **Track Results** - Update the tome with execution results

## Installation

1. **Files Already Created**:
   - `tome_ai_integration.py` - Bridge between Tome and AI
   - `ai_exploit_crafter.py` - AI exploit generation
   - `tome_ai_gui.py` - Interactive GUI tabs

2. **Add to HadesAI.py** (do this manually or I can do it):

Find line ~130 where other modules are imported and add:

```python
# Tome AI Integration
try:
    from tome_ai_gui import create_tome_ai_tab
    HAS_TOME_AI = True
except ImportError:
    create_tome_ai_tab = None
    HAS_TOME_AI = False
```

Then around line 4080 where tabs are added:

```python
if HAS_TOME_AI:
    self.tabs.addTab(create_tome_ai_tab(), "🔗 Tome-AI")
```

## Quick Usage

### For Users (GUI)

1. Open HadesAI
2. Click the "🔗 Tome-AI" tab
3. Browse categories in "📚 Knowledge Base"
4. Go to "🔧 Craft Exploit" to generate new exploits
5. View AI reasoning in "🧠 AI Reasoning"

### For AI (Programmatic)

```python
from tome_ai_integration import TomeAIBridge
from ai_exploit_crafter import AIExploitCrafter, ExploitIdea

# Initialize
bridge = TomeAIBridge()
crafter = AIExploitCrafter(bridge)

# AI reads from tome
knowledge = bridge.get_exploit_knowledge_base()
print(f"AI knows {knowledge['total_exploits']} exploits")

# AI crafts new exploit
idea = ExploitIdea(
    category="RCE",
    target_type="Apache",
    vulnerability_description="Arbitrary file upload",
    cve_ids=["CVE-2024-1234"],
    references=[],
    confidence_score=0.9
)

template = crafter.craft_exploit_from_idea(idea)
print(f"Crafted: {template.name}")

# AI saves to tome
crafter.save_crafted_exploit(template)
```

## Key Classes

### TomeAIBridge
**Read from Tome, Store AI Exploits**

```python
bridge = TomeAIBridge()

# Read
kb = bridge.get_exploit_knowledge_base()
exploits = bridge.get_exploits_by_category("XSS")
cve_exploits = bridge.get_exploits_by_cve("CVE-2024-1234")
patterns = bridge.search_exploit_patterns("RCE")
analysis = bridge.analyze_exploit_patterns()
recommendations = bridge.get_exploit_recommendations_for_target(target_info)

# Write
bridge.create_exploit_from_ai(template)
bridge.update_exploit_from_execution(exploit_id, result)
bridge.combine_exploits_for_ai(exploit_ids)

# Export
bridge.export_knowledge_for_ai("knowledge.json")
```

### AIExploitCrafter
**Generate New Exploits**

```python
crafter = AIExploitCrafter(bridge)

# Craft from various sources
template = crafter.craft_exploit_from_idea(idea)
template = crafter.craft_exploit_from_cve("CVE-X")
templates = crafter.craft_exploit_from_target_info(target)
chain = crafter.craft_exploit_chain(vulnerabilities)

# Save
crafter.save_crafted_exploit(template)

# Get suggestions
suggestions = crafter.get_crafting_suggestions()
```

### TomeAccessor
**Simple AI-friendly Interface**

```python
from tome_ai_integration import TomeAccessor

accessor = TomeAccessor(bridge)

# Quick queries
similar = accessor.get_similar_exploits("SQL Injection")
successful = accessor.get_successful_exploits("RCE", limit=5)
cve_exploits = accessor.get_cve_exploits("CVE-2024-1234")
payloads = accessor.get_payload_templates("XSS")
tactics = accessor.analyze_tactics()
```

## Example Workflows

### Workflow 1: AI Finds Vulnerability and Crafts Exploit

```python
# 1. AI scans target, finds CVE-2024-1234
cve = "CVE-2024-1234"

# 2. Query tome for existing exploits
bridge = TomeAIBridge()
existing = bridge.get_exploits_by_cve(cve)

if existing:
    print(f"Found {len(existing)} existing exploits for {cve}")
    # Use or adapt existing
else:
    # 3. Craft new exploit
    crafter = AIExploitCrafter(bridge)
    template = crafter.craft_exploit_from_cve(cve)
    
    if template:
        # 4. Save to tome
        crafter.save_crafted_exploit(template)
        print(f"Created and saved: {template.name}")
```

### Workflow 2: AI Creates Multi-Stage Attack

```python
crafter = AIExploitCrafter(TomeAIBridge())

# Define vulnerability chain
chain = [
    {
        'category': 'SQL Injection',
        'cve_ids': ['CVE-2024-1000'],
        'description': 'Database access'
    },
    {
        'category': 'RCE',
        'cve_ids': ['CVE-2024-2000'],
        'description': 'Command execution'
    }
]

# Create chain exploit
template = crafter.craft_exploit_chain(chain)

if template:
    print(f"Created chain: {template.name}")
    print(f"Stages: {len(template.payload_template.split('Stage'))}")
```

### Workflow 3: AI Analyzes What Works

```python
bridge = TomeAIBridge()

# Get analysis
analysis = bridge.analyze_exploit_patterns()

# See best categories
print("Most successful categories:")
for cat in analysis['category_performance']:
    print(f"  {cat['category']}: avg success {cat['avg_success_rate']:.1f}%")

# See most used techniques
print("\nMost used techniques:")
for tag, count in list(analysis['tag_frequency'].items())[:10]:
    print(f"  {tag}: {count} exploits")
```

## Data Structure

### ExploitTemplate (Generated by AI)

```python
@dataclass
class ExploitTemplate:
    name: str                         # "XSS in Login Form"
    category: str                     # "XSS"
    target_type: str                  # "Web Application"
    vulnerability_type: str           # "Reflected XSS"
    cve_ids: List[str]               # ["CVE-2024-1234"]
    payload_template: str            # The actual exploit code
    prerequisites: List[str]         # What's needed to run it
    success_indicators: List[str]    # How to know it worked
    references: List[str]            # URLs for more info
    tags: List[str]                  # ["xss", "web", "reflected"]
    difficulty: str                  # "easy", "medium", "hard", "expert"
```

### ExploitIdea (Input to Crafter)

```python
@dataclass
class ExploitIdea:
    category: str                    # "RCE"
    target_type: str                 # "Apache 2.4"
    vulnerability_description: str   # "Arbitrary file execution"
    cve_ids: List[str]              # ["CVE-2024-5678"]
    references: List[str]            # Links to info
    confidence_score: float          # 0.0-1.0
```

## Common Patterns

### Pattern 1: Get Recommendations for Target

```python
def recommend_exploits_for_target(target_info):
    bridge = TomeAIBridge()
    
    recommendations = bridge.get_exploit_recommendations_for_target({
        'type': 'linux_web_server',
        'cves': ['CVE-2024-1234'],
        'services': ['Apache', 'PHP']
    })
    
    return sorted(recommendations, 
                  key=lambda x: x['success_count'], 
                  reverse=True)[:5]
```

### Pattern 2: Adapt Successful Exploit

```python
def create_variant_of_successful_exploit(category):
    crafter = AIExploitCrafter(TomeAIBridge())
    
    # Get most successful exploit
    successful = crafter.accessor.get_successful_exploits(category, limit=1)
    
    if successful:
        variant = crafter._create_exploit_variant(successful[0])
        crafter.save_crafted_exploit(variant)
        return variant
```

### Pattern 3: Fill Knowledge Gaps

```python
def identify_and_fill_gaps():
    crafter = AIExploitCrafter(TomeAIBridge())
    
    suggestions = crafter.get_crafting_suggestions()
    
    for suggestion in suggestions:
        print(f"Gap: {suggestion}")
        # AI could auto-generate exploits for gaps
```

## Testing

### Test 1: Verify Connection

```python
from tome_ai_integration import TomeAIBridge

bridge = TomeAIBridge()
kb = bridge.get_exploit_knowledge_base()
print(f"✓ Connected. {kb['total_exploits']} exploits loaded")
```

### Test 2: Craft Simple Exploit

```python
from ai_exploit_crafter import AIExploitCrafter, ExploitIdea
from tome_ai_integration import TomeAIBridge

crafter = AIExploitCrafter(TomeAIBridge())

idea = ExploitIdea(
    category="XSS",
    target_type="Web App",
    vulnerability_description="Unescaped input",
    cve_ids=[],
    references=[],
    confidence_score=0.8
)

template = crafter.craft_exploit_from_idea(idea)
print(f"✓ Crafted: {template.name}")
print(f"  Difficulty: {template.difficulty}")
```

### Test 3: Save to Tome

```python
result = crafter.save_crafted_exploit(template)
print(f"✓ Saved: {result['success']}")
print(f"  ID: {result['exploit_id']}")
```

## What Happens When AI Uses This

1. **Target Scanning** → AI identifies vulnerabilities
2. **Tome Query** → Looks up similar exploits
3. **Analysis** → Understands success patterns
4. **Generation** → Creates new/adapted exploit
5. **Testing** → Executes payload
6. **Recording** → Stores result in tome
7. **Learning** → Uses updated data for next exploit

## Performance Tips

- Cache knowledge base in memory for repeated access
- Use TomeAccessor for simple queries
- Batch CVE lookups to reduce database queries
- Export knowledge periodically for analysis

## Next Steps

1. **Run tests** to verify it works
2. **Integrate into HadesAI.py** (add the imports)
3. **Test crafting** with a simple idea
4. **Monitor success rates** to see if AI exploits work
5. **Iterate** based on results

## Troubleshooting

**"No exploits found"**
- Check that exploit_tome.db exists
- Verify exploits were added via the Exploit Tome tab

**"Crafting fails"**
- Check that tome data is available
- Verify category exists in tome

**"Connection error"**
- Ensure exploit_tome.db is in correct directory
- Check database permissions

## Questions?

See `TOME_AI_INTEGRATION.md` for detailed documentation and examples.

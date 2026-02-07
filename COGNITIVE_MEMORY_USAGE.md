# Cognitive Memory System - HadesAI Integration

## Overview

The Cognitive Memory System provides embedding-based memory storage with feedback loops for reinforcement learning. It enables HadesAI to learn from interaction outcomes and improve response quality through semantic retrieval and outcome-based reinforcement.

## Features

- **Semantic Storage**: Store content with embeddings for intelligent retrieval
- **Vector Search**: Find similar memories using cosine similarity
- **Feedback Loop**: Evaluate outcomes and reinforce successful patterns
- **Reinforcement Learning**: Memory importance adjusts based on success scores
- **Memory-Augmented Generation**: Use recalled memories as context for LLM
- **Time-Based Decay**: Older memories gradually lose importance
- **Access Tracking**: Track which memories are frequently recalled
- **Background Optimization**: Async pruning and compression (1-hour intervals)
- **Metadata Support**: Attach custom metadata to each memory

## Usage Examples

### Basic Memory Operations

#### Store a Memory
```python
from HadesAI import HadesAI

hades = HadesAI()

# Store an exploitation technique with high importance
memory_id = hades.remember(
    text="SQL injection vulnerability found in user login form. Input validation missing.",
    importance=0.9,
    metadata={'type': 'vulnerability', 'cve': 'CVE-2024-XXXXX'}
)
print(f"Stored memory: {memory_id}")
```

#### Retrieve Similar Memories
```python
# Search for related security findings
results = hades.recall(
    query="SQL injection attack vectors",
    top_k=5
)

for similarity_score, memory in results:
    print(f"Score: {similarity_score:.3f}")
    print(f"Content: {memory.content}")
    print(f"Importance: {memory.importance}\n")
```

### Memory Optimization

#### Cleanup Low-Value Memories
```python
stats = hades.optimize_memory(
    prune_threshold=0.3,  # Remove memories below importance 0.3
    apply_decay=True      # Apply time-based decay
)

print(f"Pruned: {stats['pruned_count']} memories")
print(f"Before: {stats['stats_before']}")
print(f"After: {stats['stats_after']}")
```

#### Check Memory Statistics
```python
stats = hades.get_memory_stats()
print(f"Total memories: {stats['total_memories']}")
print(f"Average importance: {stats['avg_importance']:.2f}")
print(f"Oldest: {stats['oldest']}")
print(f"Newest: {stats['newest']}")
```

### Feedback Loop & Reinforcement

#### Step 1: Generate Response with Memory Context
```python
# Generate response using recalled memories
def llm_response(prompt):
    # Call your LLM with the prompt
    return "Response from LLM using memory context"

response, memories = hades.generate_with_memory(
    query="How to exploit SQL injection?",
    llm_call=llm_response
)

print(f"Response: {response}")
print(f"Used memories: {len(memories)}")
```

#### Step 2: Evaluate Outcome
```python
# After user confirms the response was helpful
success_score = 0.9  # Scale 0.0-1.0

reflection_id = hades.evaluate_response(
    user_input="How to exploit SQL injection?",
    ai_output=response,
    success_score=success_score,
    metadata={'source': 'security_audit', 'target': 'web_app'}
)

print(f"Reflection stored: {reflection_id}")
```

#### Step 3: Reinforce Specific Memories
```python
# Boost the importance of memories that contributed to success
for similarity_score, memory in memories:
    hades.reinforce_memory(memory.id, success_score=0.85)
```

#### Complete Feedback Loop Example
```python
def hades_query_with_feedback(hades, user_query, llm_func):
    """
    Complete feedback loop: generate → evaluate → reinforce
    """
    # Generate response using memory context
    response, recalled_memories = hades.generate_with_memory(
        query=user_query,
        llm_call=llm_func
    )
    
    # User evaluates the response (manual, heuristic, or automatic)
    user_satisfaction = input("Rate response (0.0-1.0): ")
    success_score = float(user_satisfaction)
    
    # Store the evaluation as a reflection
    reflection_id = hades.evaluate_response(
        user_input=user_query,
        ai_output=response,
        success_score=success_score,
        metadata={'user_feedback': True}
    )
    
    # Reinforce memories that helped
    for _, memory in recalled_memories:
        hades.reinforce_memory(memory.id, success_score)
    
    return response, reflection_id

# Use it
response, reflection_id = hades_query_with_feedback(
    hades,
    "Explain privilege escalation",
    your_llm_function
)
```

### View Feedback Statistics

#### Check Reflection Stats
```python
reflection_stats = hades.get_full_cognitive_stats()

print(f"Total interactions analyzed: {reflection_stats['reflections']['total_reflections']}")
print(f"Average success: {reflection_stats['reflections']['avg_success']:.2f}")
print(f"Recent interactions: {reflection_stats['reflections']['recent']}")
```

#### Monitor Memory Quality
```python
stats = hades.get_full_cognitive_stats()

integration = stats['integration_quality']
print(f"Reinforced memories: {integration['reinforced_memories']}")
print(f"Frequently accessed: {integration['frequently_accessed']}")
print(f"Avg reinforcement: {stats['memories']['avg_reinforcement']:.3f}")
```

### Advanced Usage

#### Custom Embedder
```python
import numpy as np
from sentence_transformers import SentenceTransformer

# Use a proper embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')
embedder = lambda text: model.encode(text).tolist()

# Set custom embedder
hades.cognitive.set_embedder(embedder)

# Now memories will use real semantic embeddings
memory_id = hades.remember(
    text="Privilege escalation through kernel vulnerability",
    importance=0.95
)
```

#### Programmatic Memory Management
```python
# Get direct access to memory store
store = hades.cognitive.store

# Check total memory count
print(f"Total stored memories: {store.size()}")

# Retrieve specific memory
memory = store.get_memory("memory-id-uuid")
if memory:
    print(f"Retrieved: {memory.content}")

# Delete specific memory
deleted = hades.forget("memory-id-uuid")
print(f"Memory deleted: {deleted}")

# Clear all memories
hades.cognitive.clear()
```

## Memory Structure

### Memory Object
```python
@dataclass
class Memory:
    id: str                  # UUID identifier
    content: str             # Memory text content
    embedding: list          # Vector embedding (128-dim default)
    importance: float        # Importance score (0.0-1.0)
    timestamp: datetime      # When memory was created
    metadata: dict          # Custom metadata
```

### Importance Levels

- **0.0-0.3**: Low-value, candidate for pruning
- **0.3-0.6**: Medium-value, general observations
- **0.6-0.8**: High-value, important findings
- **0.8-1.0**: Critical, core knowledge

## Integration with HadesAI

### In Chat/Analysis Mode
```python
# During pentesting analysis, store findings
hades.remember(
    text="XSS vulnerability in comments section. Uses dangerous innerHTML.",
    importance=0.85,
    metadata={'vulnerability_type': 'XSS', 'severity': 'high'}
)

# Later, recall similar vulnerabilities
similar = hades.recall("XSS DOM-based vulnerabilities")
```

### In Learning Mode
```python
# When learning from web sources, store knowledge
hades.remember(
    text="CVSS score calculation: Base * Temporal * Environmental",
    importance=0.5,
    metadata={'source': 'CVSS-guide', 'category': 'methodology'}
)
```

## Performance Considerations

### Memory Limits
- Default embeddings: 128 dimensions
- No hard limit on memory count (but performance degrades linearly with search)
- Recommended: Keep < 10,000 memories for optimal performance

### Optimization Strategy
```python
# Periodically optimize
if hades.cognitive.get_memory_stats()['total_memories'] > 5000:
    hades.optimize_memory(
        prune_threshold=0.25,
        apply_decay=True
    )
```

### Using Better Embedders
For production use, replace default embedder with proper model:
```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')
hades.cognitive.set_embedder(lambda x: model.encode(x).tolist())
```

## API Reference

### HadesAI Methods - Memory Storage

#### `remember(text, importance=0.5, metadata=None) -> str`
Store content in cognitive memory. Returns memory ID.

#### `recall(query, top_k=5) -> List[Tuple[float, Memory]]`
Search memories by semantic similarity with reinforcement bias. Returns list of (score, memory) tuples.

#### `forget(memory_id) -> bool`
Remove a specific memory. Returns success status.

#### `get_memory_stats() -> Dict`
Get current memory statistics (count, importance scores, timestamps).

### HadesAI Methods - Feedback Loop

#### `evaluate_response(user_input, ai_output, success_score, metadata=None) -> str`
Create a reflection from an interaction outcome. Stores evaluation and returns reflection ID.

#### `reinforce_memory(memory_id, success_score) -> bool`
Update memory's reinforcement score and importance based on feedback.

#### `generate_with_memory(query, llm_call) -> Tuple[str, List[Tuple]]`
Generate response using recalled memories as context. Returns (response, recalled_memories).

### HadesAI Methods - Optimization & Stats

#### `optimize_memory(prune_threshold=0.2, apply_decay=True) -> Dict`
Optimize storage by pruning and compressing. Returns statistics.

#### `get_full_cognitive_stats() -> Dict`
Get comprehensive statistics about memories, reflections, and integration quality.

## Future Enhancements

1. **Persistent Storage**: Save memories to SQLite database
2. **Memory Clustering**: Group similar memories automatically
3. **Hierarchical Organization**: Create memory categories
4. **Attention Mechanism**: Weight frequently-recalled memories higher
5. **Cross-Instance Sharing**: Share memories between HadesAI instances
6. **Knowledge Graph**: Connect related memories as a graph

## Dependencies

- numpy - For vector operations
- sentence-transformers (optional) - For better embeddings

## Feedback Loop Architecture

The memory feedback loop implements safe, non-invasive learning:

```
User Input
    ↓
LLM Response (augmented with recalled memories)
    ↓
Outcome Evaluation (user or heuristic-based scoring)
    ↓
Memory Reinforcement (importance ↑ / importance ↓)
    ↓
Future Recall Bias (successful memories ranked higher)
```

### How It Works

1. **Generation with Memory**: Query recalled memories and include them as context
2. **Outcome Tracking**: Evaluate success on scale 0.0-1.0
3. **Memory Update**: Adjust memory importance based on success
4. **Reinforcement Bias**: Future searches prioritize proven successful memories
5. **Time Decay**: Memories gradually lose importance if not reinforced

### Safety Properties

- **Non-invasive**: No self-modification, only memory weighting
- **Interpretable**: All reinforcement decisions are visible and auditable
- **Reversible**: Individual memories can be pruned or reset
- **Bounded**: Memory importance capped at 1.0
- **Observable**: Full statistics available for monitoring

## Troubleshooting

### Memory Not Found
```python
if not hades.cognitive:
    print("Cognitive memory system not initialized")
```

### Poor Search Results
- Use custom embedder with semantic understanding
- Increase top_k for more results
- Check memory importance scores

### Performance Issues
- Optimize memory to prune low-value entries
- Use clustering-based compression
- Consider batching large search operations

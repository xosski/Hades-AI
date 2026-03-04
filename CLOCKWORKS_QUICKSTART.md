# Clockworks Obfuscation - Quick Start Guide

## 5-Minute Setup

### Installation
No additional dependencies - uses Python standard library + existing PyQt5

### Launch GUI
```bash
python clockworks_obfuscation_gui.py
```

## Common Tasks

### Obfuscate Lua Code

1. **Open GUI** → **Obfuscation Tab**
2. **Input Area** → Paste your Lua code
3. **Settings:**
   - Seed: 7 (default)
   - Rounds: 9 (default)
   - Type: lua
4. **Click "Obfuscate"**
5. **Output** → Copy/Save result

### Obfuscate Shellcode

1. **Obfuscation Tab**
2. **Input** → Paste shellcode (as text or hex)
3. **Settings:**
   - Type: shellcode
4. **Click "Obfuscate"**
5. Copy base64 output

### Generate 10 Polymorphic Variants

1. **Polymorphic Tab**
2. **Payload** → Enter payload
3. **Variations:** 10
4. **Type:** payload
5. **Click "Generate Polymorphic Variations"**
6. Table shows all variations with different seeds/rounds

### Batch Obfuscate

1. **Batch Operations Tab**
2. **Input** (JSON format):
   ```json
   {
     "payloads": [
       "payload1",
       "payload2",
       "payload3"
     ]
   }
   ```
3. **Click "Process Batch"**
4. Results as JSON with all obfuscated variants

## Code Examples

### Python: Quick Obfuscation

```python
from modules.obfuscation_engine import ClockworksObfuscator

obf = ClockworksObfuscator(seed=7, rounds=9)
result = obf.obfuscate_lua("print('hello')")
print(result)
```

### Python: Hades Integration

```python
from modules.hades_obfuscation_integration import obfuscate_for_hades

result = obfuscate_for_hades(
    payload="my_payload",
    payload_type="payload",
    seed=7,
    rounds=9
)

print(f"Obfuscated: {result['obfuscated']}")
print(f"Size: {result['original_size']} -> {result['obfuscated_size']}")
```

### Python: Polymorphic Generation

```python
from modules.hades_obfuscation_integration import get_obfuscation_service, ObfuscationType

service = get_obfuscation_service()

variations = service.generate_polymorph_payload(
    payload="shellcode_here",
    variations=5,
    payload_type=ObfuscationType.SHELLCODE
)

for var in variations:
    print(f"Variation {var['variation']}: {var['obfuscated'][:50]}...")
```

## Settings Reference

### Seed (1-12)
- **1-12:** Clock direction initialization
- **7:** Default (recommended)
- **11:** Alternative fast variant
- Higher = different obfuscation pattern

### Rounds (1-20+)
- **9:** Default (balanced)
- **5:** Fast obfuscation
- **15:** Strong diffusion
- Higher rounds = better diffusion, slower

### Payload Types
- **lua:** Lua code with loader
- **payload:** Generic payload
- **shellcode:** Machine code
- **command:** Shell commands
- **script:** Shell scripts
- **binary:** Raw binary

## Tips & Tricks

### Maximize Entropy
```python
# High rounds for maximum diffusion
service.obfuscate_payload(payload, seed=11, rounds=15)
```

### Speed vs. Security Tradeoff
```python
# Fast: seed=1, rounds=5
# Balanced: seed=7, rounds=9 (default)
# Strong: seed=11, rounds=15
```

### Polymorphic Evasion
```python
# Generate 20+ variations to evade pattern matching
variations = service.generate_polymorph_payload(
    payload=my_payload,
    variations=20
)
```

### Batch Processing
```python
import json

payloads = ["payload1", "payload2", "payload3"]
results = service.obfuscate_batch(payloads)

# Export as JSON
with open("obfuscated.json", "w") as f:
    json.dump(results, f)
```

## Deobfuscation

### GUI Method
1. **Obfuscation Tab**
2. **Input** → Paste obfuscated data
3. **Settings** → Set same Seed/Rounds used for encryption
4. **Click "Deobfuscate"**

### Code Method
```python
obf = ClockworksObfuscator(seed=7, rounds=9)
original = obf.deobfuscate(obfuscated_data, format="b64")
```

## File Operations

### Load From File
- GUI: **Load File** button
- Code: `with open(file) as f: payload = f.read()`

### Save To File
- GUI: **Save Output** button
- Code: `with open(file, 'w') as f: f.write(output)`

## Performance

| Operation | Time |
|-----------|------|
| 1KB obfuscate | <10ms |
| 100KB obfuscate | <200ms |
| Polymorphic (10) | <100ms |
| Batch (100) | <1s |

## Troubleshooting

### GUI Won't Start
```bash
pip install PyQt5
python clockworks_obfuscation_gui.py
```

### Deobfuscation Returns Garbage
- Check Seed/Rounds match encryption
- Verify Format (hex/b64/bin) is correct
- Ensure data not corrupted

### Lua Payload Won't Execute
- Verify original Lua is valid
- Check loader template hasn't been modified
- Use CLI test first before integration

## Next Steps

1. **Integrate with attacks:** Add obfuscation to attack payloads
2. **Network sharing:** Share obfuscated payloads across network
3. **Automation:** Batch obfuscate all payloads automatically
4. **Monitoring:** Track obfuscation statistics

## Advanced Integration

### With Exploit Tome
```python
from exploit_tome import ExploitTome
from modules.hades_obfuscation_integration import get_obfuscation_service

tome = ExploitTome()
obf = get_obfuscation_service()

for exploit in tome.get_all():
    obf_payload = obf.obfuscate_payload(exploit["payload"])
    # Store obfuscated version
```

### With Autonomous Operations
```python
from modules.autonomous_operations import AutonomousOpsEngine
from modules.hades_obfuscation_integration import get_obfuscation_service

ops = AutonomousOpsEngine()
obf = get_obfuscation_service()

# Auto-obfuscate all payloads
for task in ops.get_tasks():
    task.obfuscated_payload = obf.obfuscate_payload(task.payload)
```

### With Attack Vectors
```python
from attack_vectors_engine import AttackVectorEngine
from modules.hades_obfuscation_integration import get_obfuscation_service

vectors = AttackVectorEngine()
obf = get_obfuscation_service()

# Obfuscate each vector's payload
for vector in vectors.get_all():
    obf_payload = obf.obfuscate_payload(vector.payload)
```

## Command Quick Reference

```bash
# GUI
python clockworks_obfuscation_gui.py

# Test/Demo
python -c "
from modules.obfuscation_engine import ClockworksObfuscator
obf = ClockworksObfuscator(7, 9)
print(obf.obfuscate_binary(b'test', 'b64'))
"

# Get Service
python -c "
from modules.hades_obfuscation_integration import get_obfuscation_service
svc = get_obfuscation_service()
print(svc.get_obfuscation_stats())
"
```

## Key Takeaways

✓ Clockworks obfuscation uses Clock-Direction RNG
✓ Seed (1-12) controls initial direction
✓ Rounds (1-20+) controls diffusion strength
✓ Polymorphic generation creates variations
✓ Batch operations process multiple payloads
✓ GUI and CLI interfaces available
✓ Caching improves performance
✓ Easy integration with Hades systems

## Next: Full Documentation

For complete API reference, see: `CLOCKWORKS_OBFUSCATION_INTEGRATION.md`

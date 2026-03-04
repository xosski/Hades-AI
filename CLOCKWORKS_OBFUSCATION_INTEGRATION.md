# Clockworks Obfuscation Integration - Hades AI

## Overview

The Clockworks Obfuscation Engine has been successfully integrated into Hades AI. This provides advanced payload obfuscation using a proprietary Clock-Direction RNG (driftwheel keystream) cipher.

**Key Features:**
- Clock-Direction RNG obfuscation for Lua code and binary payloads
- Polymorphic payload generation with varying seeds/rounds
- Batch obfuscation operations
- GUI and programmatic interfaces
- Caching and performance optimization

## Architecture

### Core Components

#### 1. **obfuscation_engine.py** (modules/)
The foundational obfuscation engine implementing the clock-direction RNG:

```
DriftState (dataclass)
  ├── shape: 0..5
  ├── color: 0..5
  └── direction: 1..12 (clock positions)

Functions:
  ├── _mix(a, b): Nonlinear mixer
  ├── _step(st, i): Execute driftwheel step
  ├── keystream(seed, n, rounds): Generate deterministic keystream
  ├── xor_bytes(data, ks): XOR encryption/decryption
  
ClockworksObfuscator (class)
  ├── obfuscate_lua(code): Obfuscate Lua code
  ├── obfuscate_binary(data, format): Obfuscate binary data
  └── deobfuscate(data, format): Reverse operation
```

**Seed Range:** 1-12 (clock positions)
**Rounds:** 1-20+ (diffusion iterations, default 9)

#### 2. **hades_obfuscation_integration.py** (modules/)
High-level Hades AI integration layer:

```
ObfuscationType (enum)
  ├── LUA
  ├── PAYLOAD
  ├── SHELLCODE
  ├── COMMAND
  ├── SCRIPT
  └── BINARY

HadesObfuscationIntegration (class)
  ├── obfuscate_payload(): Single payload obfuscation
  ├── deobfuscate_payload(): Reverse operation
  ├── obfuscate_batch(): Multiple payloads
  ├── generate_polymorph_payload(): Polymorphic variations
  ├── get_obfuscation_stats(): Cache statistics
  └── update_defaults(): Modify seed/rounds

Functions:
  ├── get_obfuscation_service(): Global service singleton
  └── obfuscate_for_hades(): Convenience wrapper
```

#### 3. **clockworks_obfuscation_gui.py**
PyQt5-based interactive GUI:

```
Tabs:
  ├── Obfuscation
  │   ├── Settings (Seed, Rounds, Payload Type)
  │   ├── Input area
  │   ├── Operations (Obfuscate, Deobfuscate, Load, Copy, Save)
  │   └── Output display
  ├── Polymorphic
  │   ├── Variation generation
  │   ├── Table display
  │   └── Output selection
  ├── Batch Operations
  │   ├── JSON input
  │   └── Results display
  └── Statistics
      ├── Cache statistics
      ├── Compression ratios
      └── Cache management
```

## Usage

### Command-Line Interface

```bash
# Basic obfuscation
python modules/obfuscation_engine.py < input.lua > output_obf.lua

# GUI Application
python clockworks_obfuscation_gui.py
```

### Programmatic Usage

#### Basic Obfuscation

```python
from modules.obfuscation_engine import ClockworksObfuscator

obfuscator = ClockworksObfuscator(seed=7, rounds=9)

# Obfuscate Lua code
lua_code = "print('hello')"
obfuscated = obfuscator.obfuscate_lua(lua_code)

# Obfuscate binary data
binary_data = b"shellcode here"
obfuscated = obfuscator.obfuscate_binary(binary_data, format="b64")

# Deobfuscate
original = obfuscator.deobfuscate(obfuscated, format="b64")
```

#### Hades AI Integration

```python
from modules.hades_obfuscation_integration import (
    get_obfuscation_service,
    ObfuscationType,
    obfuscate_for_hades
)

# Get the global service
service = get_obfuscation_service()

# Obfuscate a payload
result = service.obfuscate_payload(
    payload="shellcode_here",
    payload_type=ObfuscationType.SHELLCODE,
    seed=7,
    rounds=9
)

print(result)
# {
#   "type": "shellcode_obfuscated",
#   "obfuscated": "base64_encoded_data",
#   "original_size": 100,
#   "obfuscated_size": 150,
#   "seed": 7,
#   "rounds": 9
# }

# Generate polymorphic variations
variations = service.generate_polymorph_payload(
    payload="payload",
    variations=5,
    payload_type=ObfuscationType.PAYLOAD
)

# Batch obfuscation
results = service.obfuscate_batch(
    payloads=["payload1", "payload2", "payload3"],
    payload_type=ObfuscationType.COMMAND
)

# Use convenience function
result = obfuscate_for_hades(
    payload="command_here",
    payload_type="command",
    seed=7,
    rounds=9
)
```

#### Integration with Attack Vectors

```python
from modules.hades_obfuscation_integration import get_obfuscation_service
from attack_vectors_engine import AttackVectorEngine

service = get_obfuscation_service()
attack_engine = AttackVectorEngine()

# Create and obfuscate payloads
for vector in attack_engine.get_vectors():
    payload = attack_engine.craft_payload(vector)
    obfuscated = service.obfuscate_payload(payload)
    
    # Use in attack chain
    attack_engine.execute_with_payload(obfuscated["obfuscated"])
```

#### Integration with Exploit Tome

```python
from modules.hades_obfuscation_integration import get_obfuscation_service
from exploit_tome import ExploitTome

service = get_obfuscation_service()
tome = ExploitTome()

# Obfuscate stored exploits
for exploit_id in tome.list_exploits():
    exploit = tome.get_exploit(exploit_id)
    obfuscated = service.obfuscate_payload(
        exploit["payload"],
        payload_type="lua"
    )
    
    # Store obfuscated version
    tome.update_exploit(exploit_id, {
        "obfuscated_payload": obfuscated["obfuscated"],
        "seed": obfuscated["seed"],
        "rounds": obfuscated["rounds"]
    })
```

## Advanced Features

### Polymorphic Payload Generation

Generate variations of the same payload with different seeds and rounds:

```python
service = get_obfuscation_service()

variations = service.generate_polymorph_payload(
    payload="print('malware')",
    variations=10,
    payload_type=ObfuscationType.LUA
)

# Each variation has different seed/rounds
for var in variations:
    print(f"Variation {var['variation']}: seed={var['seed']}, rounds={var['rounds']}")
    print(f"Obfuscated: {var['obfuscated'][:50]}...")
```

### Payload Caching

Cached payloads are automatically reused:

```python
service = get_obfuscation_service()

# First call - will obfuscate
result1 = service.obfuscate_payload(
    "payload",
    cache_key="my_payload_v1"
)

# Second call - returns cached result
result2 = service.obfuscate_payload(
    "payload",
    cache_key="my_payload_v1"
)

assert result1 == result2  # True
```

### Statistics and Monitoring

```python
service = get_obfuscation_service()

stats = service.get_obfuscation_stats()
print(f"Cached payloads: {stats['cached_payloads']}")
print(f"Total compression: {stats['compression_ratio']:.2f}x")

# Clear cache when needed
service.clear_cache()
```

### Custom Seed/Rounds

```python
service = get_obfuscation_service()

# Update defaults for all operations
service.update_defaults(seed=11, rounds=15)

# Or specify per-operation
result = service.obfuscate_payload(
    "payload",
    seed=9,  # Custom seed
    rounds=12  # Custom rounds
)
```

## GUI Usage

### Obfuscation Tab

1. **Settings Panel:**
   - Set Seed (1-12) for RNG initialization
   - Set Rounds for diffusion iterations
   - Select Payload Type (lua, payload, shellcode, command, script, binary)

2. **Input Area:**
   - Paste payload to obfuscate/deobfuscate
   - Click "Load File" to import from disk

3. **Operations:**
   - **Obfuscate:** Encrypt payload with current settings
   - **Deobfuscate:** Decrypt using same seed/rounds
   - **Copy Output:** Copy result to clipboard
   - **Save Output:** Export to file

### Polymorphic Tab

1. Generate multiple variations automatically
2. View seed/rounds/size for each variation
3. Select and view individual variation outputs
4. Export all variations for distribution

### Batch Tab

1. Input JSON with multiple payloads:
   ```json
   {
     "payloads": [
       "payload1",
       "payload2",
       "payload3"
     ]
   }
   ```

2. Process all payloads at once
3. Export results as JSON

### Statistics Tab

- View cache hit rate
- Monitor compression ratios
- Clear cache for fresh start
- Track current default settings

## Security Considerations

**Important:** Clockworks obfuscation is designed for:
- **Basic IP protection** against casual reversing
- **Polymorphic payload generation** to evade signature detection
- **Obfuscation, not encryption** - assume determined analysis can break it

**Not suitable for:**
- Protecting sensitive cryptographic keys
- Long-term confidentiality
- Compliance with security standards

## Performance

### Benchmarks (approximate)

- **1KB payload:** <10ms
- **100KB payload:** <200ms
- **1MB payload:** <2s
- **Polymorphic generation (10 vars):** <100ms
- **Batch (100 payloads):** <1s

### Optimization Tips

1. Use payload caching for repeated obfuscation
2. Adjust rounds for speed vs. diffusion tradeoff
3. Batch operations when processing multiple payloads
4. Cache service instance (it's a singleton)

## Integration Points

### With Autonomous Operations
```python
from modules.autonomous_operations import AutonomousOpsEngine
from modules.hades_obfuscation_integration import get_obfuscation_service

ops = AutonomousOpsEngine()
obf = get_obfuscation_service()

# Obfuscate all payload generation
for task in ops.get_pending_tasks():
    payload = ops.generate_payload(task)
    task.payload = obf.obfuscate_payload(payload)["obfuscated"]
```

### With Payload Generator
```python
from payload_generator_gui import PayloadGenerator
from modules.hades_obfuscation_integration import get_obfuscation_service

gen = PayloadGenerator()
obf = get_obfuscation_service()

# Auto-obfuscate generated payloads
payload = gen.generate(target_type="web")
obfuscated = obf.obfuscate_payload(payload)
```

### With Network Share
```python
from modules.network_share_gui import NetworkShare
from modules.hades_obfuscation_integration import get_obfuscation_service

share = NetworkShare()
obf = get_obfuscation_service()

# Share obfuscated payloads across network
payloads = share.get_available_payloads()
for payload in payloads:
    obfuscated = obf.obfuscate_payload(payload)
    share.share_obfuscated(obfuscated)
```

## Testing

### Unit Tests

```python
# test_obfuscation.py
from modules.obfuscation_engine import ClockworksObfuscator

def test_roundtrip():
    obf = ClockworksObfuscator(seed=7, rounds=9)
    original = b"test data"
    encrypted = obf.obfuscate_binary(original, format="b64")
    decrypted = obf.deobfuscate(encrypted, format="b64")
    assert decrypted == original

def test_polymorphic():
    obf = ClockworksObfuscator()
    payload = "test"
    
    var1 = obf.obfuscate_lua(payload)
    obf.set_seed(11)
    var2 = obf.obfuscate_lua(payload)
    
    assert var1 != var2  # Different seeds = different outputs
```

## Troubleshooting

### GUI Won't Start
```bash
# Check PyQt5 installation
pip install PyQt5
python clockworks_obfuscation_gui.py
```

### Seed Out of Range
```python
# Automatically normalized
service = get_obfuscation_service()
service.set_seed(13)  # Becomes 1 (13 % 12 = 1, or 12 if 0)
```

### Deobfuscation Fails
- Ensure same seed/rounds used for encryption
- Verify correct format (hex, b64, bin)
- Check data integrity (no corruption)

## Files

```
Hades-AI/
├── modules/
│   ├── obfuscation_engine.py           # Core RNG engine
│   └── hades_obfuscation_integration.py # Hades integration
├── clockworks_obfuscation_gui.py        # PyQt5 GUI
└── CLOCKWORKS_OBFUSCATION_INTEGRATION.md # This file
```

## Command Reference

```bash
# Start GUI
python clockworks_obfuscation_gui.py

# Test module
python -m modules.obfuscation_engine

# Quick obfuscation
python -c "
from modules.obfuscation_engine import obfuscate
print(obfuscate(b'data', seed=7, rounds=9))
"
```

## Future Enhancements

- [ ] GPU acceleration for batch operations
- [ ] Custom RNG algorithm selection
- [ ] Real-time obfuscation metrics
- [ ] Machine learning-based payload analysis
- [ ] Integration with IDA Pro/Ghidra
- [ ] Network-based obfuscation service

## Support

For issues or questions regarding Clockworks Obfuscation integration:
1. Check the troubleshooting section
2. Review example code in this document
3. Examine test files for usage patterns
4. Check module docstrings for API details

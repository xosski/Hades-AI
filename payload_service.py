"""
Payload Service - Unified payload management
Integrates PayloadGenerator with ExploitExecutor for comprehensive vulnerability testing
Enhanced with dynamic mutation and confidence scoring
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from payload_generator_gui import PayloadGenerator
from payload_mutator import PayloadMutator, MutatedPayload
from payload_scorer import PayloadScorer, PayloadMetrics, ScoredPayload

logger = logging.getLogger("PayloadService")


class PayloadService:
    """
    Central service for managing payloads from multiple sources
    Maps vulnerability types to generated payloads
    """
    
    # Map exploit types to Payload Generator file types
    EXPLOIT_TYPE_MAPPING = {
        'sql_injection': 'sql',
        'sql_inject': 'sql',
        'sqli': 'sql',
        'injection': 'sql',  # Default to SQL
        
        'xss': 'html',
        'cross_site_scripting': 'html',
        'script_injection': 'html',
        
        'xxe': 'xml',
        'xml_injection': 'xml',
        'external_entity': 'xml',
        
        'rce': 'php',
        'remote_code_execution': 'php',
        'command_injection': 'php',
        'code_execution': 'php',
        
        'code_injection': 'python',
        'eval_injection': 'python',
        'unsafe_eval': 'python',
        
        'path_traversal': 'archive',
        'directory_traversal': 'archive',
        'file_traversal': 'archive',
        'lfi': 'archive',
        'local_file_inclusion': 'archive',
        
        'formula_injection': 'csv',
        'csv_injection': 'csv',
        'spreadsheet_injection': 'csv',
        
        'json_injection': 'json',
        'nosql_injection': 'json',
        'prototype_pollution': 'json',
        
        'xxs': 'html',  # XSS typo
        'csrf': 'html',  # CSRF payloads similar to XSS
        'security_header': 'html',
        
        'command_exec': 'php',
        'exec': 'php',
        
        'serialization': 'binary',
        'deserialization': 'binary',
        'buffer_overflow': 'binary',
        
        'template_injection': 'javascript',
        'ssti': 'javascript',
        
        'ldap_injection': 'sql',  # Similar to SQL
        'xpath_injection': 'xml',
    }
    
    def __init__(self):
        """Initialize payload service"""
        self.generator = PayloadGenerator
        self.mutator = PayloadMutator()
        self.scorer = PayloadScorer()
        
        self.cache: Dict[str, List[str]] = {}
        self.custom_payloads: Dict[str, List[str]] = {}
        self.payload_metrics: Dict[str, PayloadMetrics] = {}  # Track metrics per payload
        
        logger.info("Payload Service initialized with mutation and scoring")
        logger.debug(f"Available file types: {list(self.generator.FILE_TYPE_PATTERNS.keys())}")
    
    def get_payloads_for_vulnerability(self, vuln_type: str) -> List[str]:
        """
        Get payloads for a specific vulnerability type
        
        Args:
            vuln_type: Type of vulnerability (sql_injection, xss, etc.)
        
        Returns:
            List of relevant payloads
        
        Examples:
            >>> service = PayloadService()
            >>> sqli_payloads = service.get_payloads_for_vulnerability('sql_injection')
            >>> xss_payloads = service.get_payloads_for_vulnerability('xss')
        """
        vuln_type_normalized = vuln_type.lower().strip()
        
        # Check cache first
        if vuln_type_normalized in self.cache:
            logger.debug(f"Cache hit for {vuln_type_normalized}")
            return self.cache[vuln_type_normalized]
        
        # Check custom payloads
        if vuln_type_normalized in self.custom_payloads:
            logger.debug(f"Using custom payloads for {vuln_type_normalized}")
            return self.custom_payloads[vuln_type_normalized]
        
        # Map to file type
        file_type = self.EXPLOIT_TYPE_MAPPING.get(
            vuln_type_normalized, 
            'unknown'
        )
        
        # Get payloads from generator
        payloads = self.generator.get_payloads(file_type)
        
        # Cache result
        self.cache[vuln_type_normalized] = payloads
        
        logger.debug(f"Retrieved {len(payloads)} payloads for {vuln_type} (type: {file_type})")
        
        return payloads
    
    def get_payloads_for_detected_file(self, file_path: str) -> Dict:
        """
        Auto-detect file type and return payloads
        
        Args:
            file_path: Path to file for analysis
        
        Returns:
            Dictionary with detection result and payloads
        """
        try:
            result = self.generator.generate_payloads(file_path)
            logger.info(f"Detected {result['file_type']} with {result['count']} payloads")
            return result
        except Exception as e:
            logger.error(f"Error detecting file {file_path}: {e}")
            return {
                'file_path': file_path,
                'file_type': 'unknown',
                'payloads': [],
                'count': 0,
                'error': str(e)
            }
    
    def get_all_payloads_by_type(self) -> Dict[str, List[str]]:
        """
        Get all payloads organized by file type
        
        Returns:
            Dictionary mapping file types to payload lists
        """
        all_payloads = {}
        
        for file_type in self.generator.FILE_TYPE_PATTERNS.keys():
            payloads = self.generator.get_payloads(file_type)
            all_payloads[file_type] = payloads
        
        logger.debug(f"Retrieved payloads for {len(all_payloads)} file types")
        return all_payloads
    
    def get_payloads_by_file_type(self, file_type: str) -> List[str]:
        """
        Get payloads for a specific file type
        
        Args:
            file_type: File type (sql, xss, xml, etc.)
        
        Returns:
            List of payloads for that type
        """
        file_type_normalized = file_type.lower().strip()
        
        if file_type_normalized in self.cache:
            return self.cache[file_type_normalized]
        
        payloads = self.generator.get_payloads(file_type_normalized)
        self.cache[file_type_normalized] = payloads
        
        return payloads
    
    def filter_payloads(self, payloads: List[str], max_length: int = 1024, 
                       min_length: int = 1) -> List[str]:
        """
        Filter payloads by size constraints
        
        Args:
            payloads: List of payloads to filter
            max_length: Maximum payload length (default 1KB)
            min_length: Minimum payload length (default 1 byte)
        
        Returns:
            Filtered payload list
        """
        filtered = [
            p for p in payloads
            if min_length <= len(p) <= max_length
        ]
        
        logger.debug(f"Filtered {len(payloads)} payloads to {len(filtered)} " +
                    f"(max length: {max_length})")
        
        return filtered
    
    def get_critical_payloads(self) -> List[str]:
        """
        Get payloads for critical vulnerabilities
        Returns the most impactful payloads (RCE, XXE, etc.)
        """
        critical_types = ['php', 'xml', 'python', 'bash']
        critical_payloads = []
        
        for ftype in critical_types:
            payloads = self.generator.get_payloads(ftype)
            critical_payloads.extend(payloads)
        
        logger.info(f"Retrieved {len(critical_payloads)} critical payloads")
        return critical_payloads
    
    def register_custom_payloads(self, vuln_type: str, payloads: List[str]):
        """
        Register custom payloads for a vulnerability type
        
        Args:
            vuln_type: Vulnerability type identifier
            payloads: List of custom payloads
        """
        vuln_type_normalized = vuln_type.lower().strip()
        self.custom_payloads[vuln_type_normalized] = payloads
        
        logger.info(f"Registered {len(payloads)} custom payloads for {vuln_type}")
    
    def add_custom_payload(self, vuln_type: str, payload: str):
        """
        Add a single custom payload
        
        Args:
            vuln_type: Vulnerability type identifier
            payload: Single payload to add
        """
        vuln_type_normalized = vuln_type.lower().strip()
        
        if vuln_type_normalized not in self.custom_payloads:
            self.custom_payloads[vuln_type_normalized] = []
        
        if payload not in self.custom_payloads[vuln_type_normalized]:
            self.custom_payloads[vuln_type_normalized].append(payload)
            logger.debug(f"Added custom payload for {vuln_type}")
    
    def clear_custom_payloads(self, vuln_type: str = None):
        """
        Clear custom payloads
        
        Args:
            vuln_type: Clear only this type (None = clear all)
        """
        if vuln_type:
            vuln_type_normalized = vuln_type.lower().strip()
            if vuln_type_normalized in self.custom_payloads:
                del self.custom_payloads[vuln_type_normalized]
                logger.info(f"Cleared custom payloads for {vuln_type}")
        else:
            self.custom_payloads.clear()
            logger.info("Cleared all custom payloads")
    
    def get_payload_count_by_type(self) -> Dict[str, int]:
        """
        Get count of payloads per type
        
        Returns:
            Dictionary mapping file types to payload counts
        """
        counts = {}
        
        for file_type in self.generator.FILE_TYPE_PATTERNS.keys():
            payloads = self.generator.get_payloads(file_type)
            counts[file_type] = len(payloads)
        
        return counts
    
    def get_total_payload_count(self) -> int:
        """Get total number of available payloads"""
        counts = self.get_payload_count_by_type()
        return sum(counts.values())
    
    def search_payloads(self, query: str) -> List[Dict]:
        """
        Search for payloads by keyword
        
        Args:
            query: Search term (case-insensitive)
        
        Returns:
            List of matching payloads with their types
        """
        query_lower = query.lower()
        results = []
        
        for file_type, payloads in self.get_all_payloads_by_type().items():
            for payload in payloads:
                if query_lower in payload.lower():
                    results.append({
                        'payload': payload,
                        'file_type': file_type,
                        'length': len(payload)
                    })
        
        logger.debug(f"Found {len(results)} payloads matching '{query}'")
        return results
    
    def export_payloads_as_json(self) -> str:
        """
        Export all payloads as JSON
        
        Returns:
            JSON string with all payloads
        """
        import json
        
        all_payloads = self.get_all_payloads_by_type()
        
        export_data = {
            'total_payloads': self.get_total_payload_count(),
            'payload_types': self.get_payload_count_by_type(),
            'payloads': all_payloads
        }
        
        return json.dumps(export_data, indent=2)
    
    def get_payloads_for_target(self, target_info: Dict) -> List[str]:
        """
        Intelligently select payloads based on target information
        
        Args:
            target_info: Dictionary with target details
                - 'technology': 'PHP', 'Python', 'Java', etc.
                - 'file_type': 'html', 'json', 'xml', etc.
                - 'vulnerability': 'xss', 'injection', etc.
        
        Returns:
            List of most relevant payloads
        """
        payloads = []
        
        # If vulnerability type specified
        if 'vulnerability' in target_info:
            vuln_payloads = self.get_payloads_for_vulnerability(
                target_info['vulnerability']
            )
            payloads.extend(vuln_payloads)
        
        # If file type specified
        if 'file_type' in target_info:
            type_payloads = self.get_payloads_by_file_type(
                target_info['file_type']
            )
            payloads.extend(type_payloads)
        
        # If technology specified
        if 'technology' in target_info:
            tech = target_info['technology'].lower()
            
            if 'php' in tech:
                payloads.extend(self.get_payloads_by_file_type('php'))
            elif 'python' in tech:
                payloads.extend(self.get_payloads_by_file_type('python'))
            elif 'java' in tech:
                # Use similar payloads
                payloads.extend(self.get_payloads_by_file_type('binary'))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                unique_payloads.append(p)
                seen.add(p)
        
        logger.debug(f"Selected {len(unique_payloads)} payloads for target")
        return unique_payloads
    
    # New methods for mutation and scoring
    
    def get_mutated_payloads(
        self,
        payload: str,
        technology: Optional[str] = None,
        target_waf: Optional[str] = None,
        max_mutations: int = 10
    ) -> List[Tuple[str, float]]:
        """
        Get mutated variants of a payload for WAF evasion
        
        Args:
            payload: Original payload
            technology: Target technology stack
            target_waf: Specific WAF to target
            max_mutations: Maximum variants to generate
        
        Returns:
            List of (mutated_payload, bypass_probability) tuples
        """
        mutations = self.mutator.generate_mutations(
            payload,
            technology=technology,
            target_waf=target_waf,
            max_mutations=max_mutations
        )
        
        # Rank and return
        ranked = self.mutator.rank_mutations(mutations, target_waf)
        
        logger.info(f"Generated {len(mutations)} mutations for payload")
        return [(m.mutated, score) for m, score in ranked]
    
    def get_scored_payloads(
        self,
        payloads: List[str],
        exploit_type: str,
        target_technologies: Optional[List[str]] = None,
        target_waf: Optional[str] = None,
        top_n: Optional[int] = None
    ) -> List[Tuple[str, float]]:
        """
        Score payloads by confidence and return ranked list
        
        Args:
            payloads: List of payloads to score
            exploit_type: Type of exploit (sql_injection, xss, etc.)
            target_technologies: Technologies to match
            target_waf: WAF to target
            top_n: Return only top N payloads
        
        Returns:
            List of (payload, confidence_score) tuples
        """
        # Convert to metrics
        metrics_list = []
        for payload in payloads:
            metrics = self.payload_metrics.get(payload)
            
            if not metrics:
                # Create default metrics
                metrics = PayloadMetrics(
                    payload=payload,
                    exploit_type=exploit_type,
                    source='static',
                    confidence=0.6
                )
                if target_technologies:
                    metrics.target_technologies = target_technologies
            
            metrics_list.append(metrics)
        
        # Score them
        scored = self.scorer.score_payloads(
            metrics_list,
            target_technologies=target_technologies,
            target_waf=target_waf,
            sort=True
        )
        
        # Return top N if specified
        if top_n:
            scored = scored[:top_n]
        
        logger.info(f"Scored {len(scored)} payloads")
        return [(sp.metrics.payload, sp.final_score) for sp in scored]
    
    def get_intelligent_payloads(
        self,
        target_info: Dict,
        apply_mutations: bool = True,
        apply_scoring: bool = True,
        max_payloads: int = 20
    ) -> List[Dict]:
        """
        Get payloads with mutations and confidence scores
        
        Args:
            target_info: Target details
            apply_mutations: Generate WAF evasion variants
            apply_scoring: Rank by confidence
            max_payloads: Maximum payloads to return
        
        Returns:
            List of payload dicts with metadata
        """
        # Get base payloads
        payloads = self.get_payloads_for_target(target_info)
        
        technology = target_info.get('technology')
        target_waf = target_info.get('waf')
        vuln_type = target_info.get('vulnerability', 'unknown')
        
        results = []
        
        for payload in payloads[:max_payloads]:
            payload_dict = {
                'payload': payload,
                'exploit_type': vuln_type,
                'base_payload': payload,
                'mutations': []
            }
            
            # Apply mutations
            if apply_mutations:
                mutations = self.get_mutated_payloads(
                    payload,
                    technology=technology,
                    target_waf=target_waf,
                    max_mutations=5
                )
                payload_dict['mutations'] = [
                    {'variant': m, 'bypass_probability': prob}
                    for m, prob in mutations
                ]
            
            results.append(payload_dict)
        
        # Apply scoring
        if apply_scoring:
            base_payloads = [r['payload'] for r in results]
            scores = self.get_scored_payloads(
                base_payloads,
                vuln_type,
                target_technologies=target_info.get('technologies', []),
                target_waf=target_waf,
                top_n=max_payloads
            )
            
            # Add scores to results
            score_dict = {p: s for p, s in scores}
            for result in results:
                result['confidence_score'] = score_dict.get(result['payload'], 0.5)
            
            # Sort by confidence
            results = sorted(results, key=lambda x: x['confidence_score'], reverse=True)
        
        logger.info(f"Prepared {len(results)} intelligent payloads")
        return results
    
    def track_payload_execution(
        self,
        payload: str,
        exploit_type: str,
        success: bool,
        target_technologies: Optional[List[str]] = None,
        waf_name: Optional[str] = None
    ):
        """
        Track execution results to improve future scoring
        
        Args:
            payload: The payload that was executed
            exploit_type: Type of exploit
            success: Whether execution was successful
            target_technologies: Technologies on target
            waf_name: WAF that was present (if any)
        """
        # Get or create metrics
        if payload not in self.payload_metrics:
            self.payload_metrics[payload] = PayloadMetrics(
                payload=payload,
                exploit_type=exploit_type
            )
        
        metrics = self.payload_metrics[payload]
        
        # Update metrics
        metrics.execution_count += 1
        if success:
            metrics.successful_executions += 1
        
        metrics.last_used = datetime.now()
        metrics.use_frequency += 1
        
        # Update success rate
        metrics.historical_success_rate = (
            metrics.successful_executions / metrics.execution_count
        )
        
        # Track WAF bypass if applicable
        if waf_name and success:
            current_rate = metrics.waf_bypass_history.get(waf_name, 0)
            metrics.waf_bypass_history[waf_name] = current_rate + 0.1
            metrics.avg_waf_bypass_rate = sum(
                metrics.waf_bypass_history.values()
            ) / len(metrics.waf_bypass_history)
        
        logger.debug(
            f"Tracked execution: {payload[:30]}... "
            f"success={success}, count={metrics.execution_count}"
        )
    
    def get_payload_statistics(self) -> Dict:
        """Get statistics about tracked payloads"""
        if not self.payload_metrics:
            return {}
        
        metrics_list = list(self.payload_metrics.values())
        
        avg_success_rate = sum(
            m.successful_executions / max(m.execution_count, 1)
            for m in metrics_list
        ) / len(metrics_list)
        
        total_executions = sum(m.execution_count for m in metrics_list)
        total_successes = sum(m.successful_executions for m in metrics_list)
        
        return {
            'tracked_payloads': len(self.payload_metrics),
            'total_executions': total_executions,
            'total_successes': total_successes,
            'overall_success_rate': total_successes / max(total_executions, 1),
            'average_success_rate': avg_success_rate,
            'most_used_payloads': sorted(
                metrics_list,
                key=lambda m: m.use_frequency,
                reverse=True
            )[:5]
        }


# Convenience functions
def create_payload_service() -> PayloadService:
    """Factory function to create PayloadService"""
    return PayloadService()


def get_payloads_for_type(vuln_type: str) -> List[str]:
    """Convenience function - get payloads without creating service"""
    service = PayloadService()
    return service.get_payloads_for_vulnerability(vuln_type)


if __name__ == "__main__":
    # Test the payload service
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 70)
    print("=== Enhanced Payload Service Test ===")
    print("=" * 70 + "\n")
    
    service = PayloadService()
    
    # Test 1: Basic payload retrieval
    print("Test 1: SQL Injection Payloads")
    sqli_payloads = service.get_payloads_for_vulnerability('sql_injection')
    print(f"  Found {len(sqli_payloads)} payloads:")
    for i, payload in enumerate(sqli_payloads[:2], 1):
        print(f"    {i}. {payload[:60]}...")
    
    # Test 2: Get WAF evasion mutations
    print("\n" + "=" * 70)
    print("Test 2: WAF Evasion Mutations")
    sample_payload = "' OR '1'='1' --"
    print(f"  Original: {sample_payload}")
    print(f"  Target: PHP with ModSecurity WAF\n")
    
    mutations = service.get_mutated_payloads(
        sample_payload,
        technology='php',
        target_waf='modsecurity',
        max_mutations=5
    )
    
    for i, (variant, prob) in enumerate(mutations[:4], 1):
        print(f"    {i}. Bypass Prob: {prob:.2%}")
        print(f"       {variant[:65]}...")
    
    # Test 3: Confidence scoring
    print("\n" + "=" * 70)
    print("Test 3: Payload Confidence Scoring")
    
    payloads_to_score = sqli_payloads[:5]
    scored = service.get_scored_payloads(
        payloads_to_score,
        exploit_type='sql_injection',
        target_technologies=['PHP', 'MySQL'],
        top_n=3
    )
    
    print("  Top scored payloads:\n")
    for i, (payload, score) in enumerate(scored, 1):
        print(f"    {i}. Score: {score:.3f}")
        print(f"       {payload[:60]}...")
    
    # Test 4: Intelligent payload generation with mutations + scoring
    print("\n" + "=" * 70)
    print("Test 4: Intelligent Payload Selection (Mutations + Scoring)")
    
    target_info = {
        'technology': 'PHP',
        'vulnerability': 'sql_injection',
        'waf': 'modsecurity',
        'technologies': ['PHP', 'MySQL']
    }
    
    intelligent_payloads = service.get_intelligent_payloads(
        target_info,
        apply_mutations=True,
        apply_scoring=True,
        max_payloads=3
    )
    
    for i, payload_dict in enumerate(intelligent_payloads, 1):
        print(f"\n  {i}. Confidence: {payload_dict['confidence_score']:.3f}")
        print(f"     Base: {payload_dict['payload'][:50]}...")
        if payload_dict['mutations']:
            print(f"     Variants ({len(payload_dict['mutations'])}):")
            for mut in payload_dict['mutations'][:2]:
                print(f"       • {mut['variant'][:40]}... (bypass: {mut['bypass_probability']:.2%})")
    
    # Test 5: Execution tracking
    print("\n" + "=" * 70)
    print("Test 5: Payload Execution Tracking")
    
    # Simulate some executions
    test_payload = sqli_payloads[0]
    service.track_payload_execution(
        test_payload,
        'sql_injection',
        success=True,
        target_technologies=['PHP', 'MySQL'],
        waf_name='modsecurity'
    )
    service.track_payload_execution(
        test_payload,
        'sql_injection',
        success=True,
        target_technologies=['PHP', 'MySQL'],
        waf_name='modsecurity'
    )
    service.track_payload_execution(
        test_payload,
        'sql_injection',
        success=False,
        target_technologies=['PHP', 'MySQL'],
        waf_name='modsecurity'
    )
    
    stats = service.get_payload_statistics()
    if stats:
        print(f"\n  Tracked payloads: {stats['tracked_payloads']}")
        print(f"  Total executions: {stats['total_executions']}")
        print(f"  Total successes: {stats['total_successes']}")
        print(f"  Overall success rate: {stats['overall_success_rate']:.1%}")
    
    print("\n" + "=" * 70)
    print("=== All Tests Complete ===")
    print("=" * 70)

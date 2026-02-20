"""
Payload Service - Unified payload management
Integrates PayloadGenerator with ExploitExecutor for comprehensive vulnerability testing
"""

import logging
from typing import Dict, List, Optional
from payload_generator_gui import PayloadGenerator

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
        self.cache: Dict[str, List[str]] = {}
        self.custom_payloads: Dict[str, List[str]] = {}
        
        logger.info("Payload Service initialized")
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
    
    print("=== Payload Service Test ===\n")
    
    service = PayloadService()
    
    # Test 1: Get payloads by vulnerability type
    print("Test 1: SQL Injection Payloads")
    sqli_payloads = service.get_payloads_for_vulnerability('sql_injection')
    print(f"  Found {len(sqli_payloads)} payloads:")
    for i, payload in enumerate(sqli_payloads[:3], 1):
        print(f"    {i}. {payload[:60]}...")
    
    # Test 2: Get XSS payloads
    print("\nTest 2: XSS Payloads")
    xss_payloads = service.get_payloads_for_vulnerability('xss')
    print(f"  Found {len(xss_payloads)} payloads")
    
    # Test 3: Get all payloads by type
    print("\nTest 3: All Payloads by Type")
    all_counts = service.get_payload_count_by_type()
    total = service.get_total_payload_count()
    print(f"  Total payloads: {total}")
    for ftype, count in all_counts.items():
        print(f"    {ftype}: {count}")
    
    # Test 4: Search payloads
    print("\nTest 4: Search Payloads")
    results = service.search_payloads('alert')
    print(f"  Found {len(results)} payloads containing 'alert'")
    
    # Test 5: Custom payloads
    print("\nTest 5: Custom Payloads")
    service.register_custom_payloads('sql_injection', 
                                     ["'; WAITFOR DELAY '00:00:10'--"])
    custom = service.get_payloads_for_vulnerability('sql_injection')
    print(f"  Total SQL payloads (with custom): {len(custom)}")
    
    # Test 6: Target-based selection
    print("\nTest 6: Target-Based Payload Selection")
    target_info = {
        'technology': 'PHP',
        'vulnerability': 'rce',
        'file_type': 'php'
    }
    target_payloads = service.get_payloads_for_target(target_info)
    print(f"  Selected {len(target_payloads)} payloads for PHP RCE target")
    
    print("\n=== All Tests Complete ===")

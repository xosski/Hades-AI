"""
Cache Scanner Integration for HadesAI
- Integrates EnhancedCacheScanner with HadesAI.py
- Provides UI callbacks for detailed code viewing
- Handles exploit learning and matching
"""

import os
from typing import Dict, List, Callable, Optional
from cache_scanner_enhanced import EnhancedCacheScanner


class CacheScannerIntegration:
    """Bridge between HadesAI and EnhancedCacheScanner"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.scanner = EnhancedCacheScanner(db_path)
        self.callbacks = {}
        self.current_scan_results = []
        
    def register_callback(self, event: str, callback: Callable):
        """Register UI callback for scanner events"""
        if event not in self.callbacks:
            self.callbacks[event] = []
        self.callbacks[event].append(callback)
    
    def _emit_event(self, event: str, data: Dict):
        """Emit event to registered callbacks"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                try:
                    callback(data)
                except Exception as e:
                    print(f"[!] Callback error: {e}")
    
    def initialize_scanner(self) -> bool:
        """Initialize scanner and load learned exploits"""
        try:
            count = self.scanner.load_learned_exploits()
            self._emit_event('scanner_ready', {
                'status': 'ready',
                'learned_exploits': count,
                'exploit_types': list(self.scanner.learned_exploits.keys())
            })
            return True
        except Exception as e:
            self._emit_event('scanner_error', {'error': str(e)})
            return False
    
    def scan_browser_caches(self, browsers: Optional[List[str]] = None) -> Dict:
        """Scan browser caches with full code visibility"""
        if not browsers:
            browsers = ['Chrome', 'Edge', 'Firefox', 'Brave', 'Opera']
        
        results = {
            'total_files': 0,
            'total_threats': 0,
            'browsers_scanned': 0,
            'findings_by_browser': {},
            'threat_details': []
        }
        
        try:
            for browser in browsers:
                cache_paths = self._get_browser_cache_paths(browser)
                if not cache_paths:
                    continue
                
                results['browsers_scanned'] += 1
                browser_findings = []
                
                for cache_path in cache_paths:
                    if not os.path.exists(cache_path):
                        continue
                    
                    # Scan directory
                    for root, dirs, files in os.walk(cache_path):
                        for filename in files[:100]:  # Limit files per scan
                            filepath = os.path.join(root, filename)
                            
                            try:
                                scan_result = self.scanner.scan_cache_with_details(filepath, browser)
                                results['total_files'] += 1
                                
                                if scan_result['detections']:
                                    results['total_threats'] += len(scan_result['detections'])
                                    browser_findings.append(scan_result)
                                    
                                    # Emit detailed finding
                                    for detection in scan_result['detections']:
                                        self._emit_event('threat_detected', {
                                            'browser': browser,
                                            'path': filepath,
                                            'threat_type': detection['threat_type'],
                                            'severity': detection['severity'],
                                            'code_visible': scan_result['code_visible'],
                                            'full_code_available': bool(scan_result['full_content'])
                                        })
                                        
                                        results['threat_details'].append({
                                            'browser': browser,
                                            'path': filepath,
                                            'threat_type': detection['threat_type'],
                                            'severity': detection['severity'],
                                            'matched_code': detection['matched_code'],
                                            'full_context': detection['full_context']
                                        })
                            except Exception as e:
                                pass
                
                if browser_findings:
                    results['findings_by_browser'][browser] = browser_findings
                    self._emit_event('browser_scan_complete', {
                        'browser': browser,
                        'findings': len(browser_findings),
                        'threats': sum(len(f['detections']) for f in browser_findings)
                    })
        
        except Exception as e:
            self._emit_event('scan_error', {'error': str(e)})
        
        self.current_scan_results = results
        self._emit_event('scan_complete', results)
        return results
    
    def get_threat_details(self, threat_id: int) -> Optional[Dict]:
        """Get full details of a specific threat including code"""
        try:
            detections = self.scanner.get_cache_detections(limit=1000)
            for detection in detections:
                if detection['id'] == threat_id:
                    return {
                        'id': detection['id'],
                        'threat_type': detection['threat_type'],
                        'severity': detection['severity'],
                        'path': detection['cache_path'],
                        'browser': detection['browser'],
                        'detected_at': detection['detected_at'],
                        'file_hash': detection['file_hash'],
                        'file_size': detection['file_size'],
                        'code_snippet': detection['code_snippet'],
                        'full_code': detection['full_code'],
                        'context_before': detection['context_before'],
                        'context_after': detection['context_after'],
                        'matched_exploit_id': detection['matched_exploit_id']
                    }
        except Exception as e:
            print(f"[!] Error getting threat details: {e}")
        
        return None
    
    def get_exploit_code(self, exploit_type: str) -> List[Dict]:
        """Get full code for learned exploit type"""
        try:
            details = self.scanner.get_exploit_details(exploit_type)
            return [{
                'id': d['id'],
                'code': d['code'],
                'description': d['description'],
                'severity': d['severity'],
                'source': d['source_url'],
                'learned_at': d['learned_at'],
                'occurrences': d['occurrence_count']
            } for d in details]
        except Exception as e:
            print(f"[!] Error getting exploit code: {e}")
            return []
    
    def get_threat_summary(self) -> Dict:
        """Get summary of all threats with code visibility"""
        try:
            summary = self.scanner.get_threat_summary()
            return {
                'total_threats': summary.get('total_detections', 0),
                'by_severity': summary.get('by_severity', {}),
                'by_threat_type': summary.get('by_threat_type', {}),
                'by_browser': summary.get('by_browser', {}),
                'learned_exploits': summary.get('learned_exploits_count', 0),
                'exploit_types': summary.get('exploit_types', [])
            }
        except Exception as e:
            print(f"[!] Error getting threat summary: {e}")
            return {}
    
    def get_browser_findings_formatted(self, browser: str) -> str:
        """Get formatted findings for a browser"""
        try:
            if browser not in self.current_scan_results.get('findings_by_browser', {}):
                return f"No findings for {browser}"
            
            findings = self.current_scan_results['findings_by_browser'][browser]
            output = f"\n{'='*60}\n{browser} Cache Findings\n{'='*60}\n\n"
            
            for finding in findings:
                if finding['detections']:
                    output += f"File: {finding['path']}\n"
                    output += f"Size: {finding.get('size', 'N/A')} bytes\n"
                    output += f"Hash: {finding.get('file_hash', 'N/A')}\n\n"
                    
                    for detection in finding['detections']:
                        output += f"  [{detection['severity']}] {detection['threat_type']}\n"
                        output += f"  Matched Code: {detection['matched_code']}\n"
                        output += f"  Position: {detection['position']}\n"
                        output += f"  Context:\n"
                        output += f"    Before: ...{detection['context_before'][-50:]}\n"
                        output += f"    After:  {detection['context_after'][:50]}...\n"
                        output += f"  Full Context:\n{detection['full_context']}\n\n"
            
            return output
        except Exception as e:
            return f"Error formatting findings: {e}"
    
    def export_all_findings(self, output_dir: str = ".") -> bool:
        """Export all findings in multiple formats"""
        try:
            json_path = os.path.join(output_dir, "cache_findings.json")
            html_path = os.path.join(output_dir, "cache_findings.html")
            
            success = True
            success &= self.scanner.export_findings_to_json(json_path)
            success &= self.scanner.export_findings_to_html(html_path)
            
            self._emit_event('export_complete', {
                'json_path': json_path,
                'html_path': html_path,
                'success': success
            })
            
            return success
        except Exception as e:
            self._emit_event('export_error', {'error': str(e)})
            return False
    
    def _get_browser_cache_paths(self, browser: str) -> List[str]:
        """Get cache paths for a browser"""
        local = os.environ.get('LOCALAPPDATA', '')
        roaming = os.environ.get('APPDATA', '')
        
        paths_map = {
            'Chrome': [os.path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Cache')],
            'Edge': [os.path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache')],
            'Firefox': [os.path.join(roaming, 'Mozilla', 'Firefox', 'Profiles')],
            'Brave': [os.path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Cache')],
            'Opera': [os.path.join(roaming, 'Opera Software', 'Opera Stable', 'Cache')],
        }
        
        return [p for p in paths_map.get(browser, []) if p]
    
    def close(self):
        """Cleanup resources"""
        self.scanner.close()


# Example usage with HadesAI integration
def example_hades_integration():
    """Example of how to integrate with HadesAI"""
    integration = CacheScannerIntegration()
    
    # Register UI callbacks
    def on_threat_detected(data):
        print(f"[THREAT] {data['browser']}: {data['threat_type']} ({data['severity']})")
        print(f"         Code Visible: {data['code_visible']}")
        if data['full_code_available']:
            print(f"         Full Code Available: YES")
    
    def on_scan_complete(data):
        print(f"\n[SCAN COMPLETE]")
        print(f"  Files Scanned: {data['total_files']}")
        print(f"  Threats Found: {data['total_threats']}")
        print(f"  Browsers Scanned: {data['browsers_scanned']}")
    
    integration.register_callback('threat_detected', on_threat_detected)
    integration.register_callback('scan_complete', on_scan_complete)
    
    # Initialize and scan
    if integration.initialize_scanner():
        print("[+] Scanner initialized")
        print(f"[+] Loaded learned exploits: {integration.scanner.load_learned_exploits()}")
        
        # Run scan
        print("\n[+] Starting cache scan...")
        results = integration.scan_browser_caches()
        
        # Get summary
        summary = integration.get_threat_summary()
        print(f"\n[SUMMARY] Total threats: {summary['total_threats']}")
        print(f"[SUMMARY] Exploit types: {summary['exploit_types']}")
        
        # Export findings
        integration.export_all_findings()
    
    integration.close()


if __name__ == "__main__":
    example_hades_integration()

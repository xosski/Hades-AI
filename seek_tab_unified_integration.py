"""
Unified Integration Layer for Seek Tab, Payload Generation, and Exploit Tome
Ensures automatic updates and seamless payload selection for exploit seeking
"""

import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime
from exploit_tome import ExploitTome, ExploitEntry
from payload_service import PayloadService
import hashlib
import uuid

logger = logging.getLogger("SeekTabUnifiedIntegration")


class UnifiedSeekIntegration:
    """
    Central integration hub that synchronizes:
    - Exploit Seek Tab (discovering exploits)
    - Payload Generation Service (creating smart payloads)
    - Exploit Tome (storing and tracking successful exploits)
    """
    
    def __init__(self, exploit_tome: ExploitTome = None, payload_service: PayloadService = None):
        """
        Initialize unified integration
        
        Args:
            exploit_tome: ExploitTome instance for storing exploits
            payload_service: PayloadService instance for payload generation
        """
        self.exploit_tome = exploit_tome or ExploitTome()
        self.payload_service = payload_service or PayloadService()
        
        # Tracking
        self.active_seeks = {}  # Track ongoing seeks
        self.exploit_callbacks = []  # Callbacks when exploits are found
        
        logger.info("Unified Seek Integration initialized")
    
    # ========== CALLBACK MANAGEMENT ==========
    
    def register_exploit_callback(self, callback: Callable[[Dict], None]):
        """
        Register callback to fire when exploits are found/added to tome
        
        Args:
            callback: Function that takes dict with exploit data
        """
        self.exploit_callbacks.append(callback)
        logger.debug(f"Registered exploit callback: {callback.__name__}")
    
    def _notify_callbacks(self, exploit_data: Dict):
        """Notify all registered callbacks of new exploit"""
        for callback in self.exploit_callbacks:
            try:
                callback(exploit_data)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    # ========== PAYLOAD SELECTION ==========
    
    def get_smart_payloads_for_exploit_seeking(
        self,
        target_url: str,
        detected_technologies: Optional[List[str]] = None,
        detected_waf: Optional[str] = None,
        vulnerability_types: Optional[List[str]] = None
    ) -> Dict[str, List[Dict]]:
        """
        Get intelligently selected payloads for exploit seeking
        Uses payload service to select best payloads for each exploit type
        
        Args:
            target_url: Target being tested
            detected_technologies: Tech stack (PHP, Django, etc.)
            detected_waf: WAF type if detected
            vulnerability_types: Specific vuln types to focus on
        
        Returns:
            Dict mapping exploit types to payload lists
        """
        smart_payloads = {}
        
        # Default vuln types if not specified
        if not vulnerability_types:
            vulnerability_types = [
                'sql_injection',
                'xss',
                'rce',
                'xxe',
                'path_traversal',
                'authentication_bypass',
                'command_injection'
            ]
        
        for vuln_type in vulnerability_types:
            try:
                # Prepare target info
                target_info = {
                    'url': target_url,
                    'technology': detected_technologies[0] if detected_technologies else None,
                    'technologies': detected_technologies or [],
                    'waf': detected_waf,
                    'vulnerability': vuln_type
                }
                
                # Get intelligent payloads with mutations + scoring
                intelligent = self.payload_service.get_intelligent_payloads(
                    target_info,
                    apply_mutations=True,
                    apply_scoring=True,
                    max_payloads=5
                )
                
                smart_payloads[vuln_type] = intelligent
                
                logger.debug(
                    f"Retrieved {len(intelligent)} smart payloads for {vuln_type} "
                    f"(WAF: {detected_waf})"
                )
                
            except Exception as e:
                logger.warning(f"Failed to get payloads for {vuln_type}: {e}")
                # Fallback to basic payloads
                try:
                    basic = self.payload_service.get_payloads_for_vulnerability(vuln_type)
                    smart_payloads[vuln_type] = [
                        {'payload': p, 'confidence_score': 0.5} 
                        for p in basic[:5]
                    ]
                except Exception as e2:
                    logger.error(f"Fallback payload retrieval failed: {e2}")
        
        return smart_payloads
    
    def prepare_payload_variants(
        self,
        base_payload: str,
        technology: Optional[str] = None,
        waf: Optional[str] = None
    ) -> List[Dict]:
        """
        Get WAF-evading variants of a payload
        
        Args:
            base_payload: Base payload to mutate
            technology: Target technology
            waf: WAF type to evade
        
        Returns:
            List of variant dicts with mutation info
        """
        variants = []
        
        try:
            mutations = self.payload_service.get_mutated_payloads(
                base_payload,
                technology=technology,
                target_waf=waf,
                max_mutations=5
            )
            
            for variant, bypass_prob in mutations:
                variants.append({
                    'payload': variant,
                    'bypass_probability': bypass_prob,
                    'base': base_payload
                })
            
            logger.debug(f"Generated {len(variants)} payload variants")
            
        except Exception as e:
            logger.error(f"Payload mutation failed: {e}")
        
        return variants
    
    # ========== EXPLOIT DISCOVERY & STORAGE ==========
    
    def process_discovered_exploit(
        self,
        target_url: str,
        exploit_data: Dict,
        source: str = "seek_tab"
    ) -> bool:
        """
        Process a discovered exploit and add to tome if valid
        
        Args:
            target_url: Target that was exploited
            exploit_data: Exploit details dict
            source: Source of discovery (seek_tab, ai_testing, etc.)
        
        Returns:
            Success boolean
        """
        try:
            # Validate exploit data
            exploit_type = exploit_data.get('exploit_type', 'Unknown')
            payload = exploit_data.get('payload', '')
            success = exploit_data.get('success', False)
            
            if not payload:
                logger.warning("Cannot add exploit without payload")
                return False
            
            # Generate unique ID
            exploit_id = self._generate_exploit_id(target_url, exploit_type, payload)
            
            # Create exploit entry
            entry = ExploitEntry(
                id=exploit_id,
                name=f"{exploit_type.upper()} - {target_url}",
                category=exploit_type,
                target=target_url,
                payload=payload,
                success_count=1 if success else 0,
                fail_count=0 if success else 1,
                created_at=datetime.now().isoformat(),
                status="active",
                notes=f"Discovered via {source}",
                tags=[source, exploit_type, target_url.split('/')[2]],  # domain as tag
                cve_ids=exploit_data.get('cve_ids', []),
                reference_links=exploit_data.get('reference_links', [])
            )
            
            # Add to tome
            added = self.exploit_tome.add_exploit(entry)
            
            if added:
                logger.info(
                    f"Exploit added to tome: {exploit_id} "
                    f"({exploit_type}, success={success})"
                )
                
                # Track payload execution
                self.payload_service.track_payload_execution(
                    payload,
                    exploit_type,
                    success=success,
                    target_technologies=exploit_data.get('technologies', []),
                    waf_name=exploit_data.get('waf', None)
                )
                
                # Notify callbacks
                self._notify_callbacks({
                    'action': 'exploit_discovered',
                    'exploit_id': exploit_id,
                    'exploit_type': exploit_type,
                    'target': target_url,
                    'success': success,
                    'source': source,
                    'timestamp': datetime.now().isoformat()
                })
            
            return added
            
        except Exception as e:
            logger.error(f"Failed to process discovered exploit: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def add_batch_exploits(
        self,
        target_url: str,
        exploits: List[Dict],
        source: str = "seek_tab"
    ) -> int:
        """
        Add multiple discovered exploits at once
        
        Args:
            target_url: Target URL
            exploits: List of exploit dicts
            source: Source of discovery
        
        Returns:
            Number of exploits successfully added
        """
        added_count = 0
        
        for exploit_data in exploits:
            if self.process_discovered_exploit(target_url, exploit_data, source):
                added_count += 1
        
        logger.info(f"Batch added {added_count}/{len(exploits)} exploits to tome")
        return added_count
    
    def _generate_exploit_id(self, target: str, exp_type: str, payload: str) -> str:
        """Generate unique ID for exploit"""
        data = f"{target}:{exp_type}:{payload}".encode()
        return hashlib.md5(data).hexdigest()
    
    # ========== SEEK RESULT ENHANCEMENT ==========
    
    def enhance_seek_results(
        self,
        seek_results: Dict,
        target_url: str
    ) -> Dict:
        """
        Enhance seek results with payload info and tome integration
        
        Args:
            seek_results: Results from exploit seeking
            target_url: Target being tested
        
        Returns:
            Enhanced results with payload details and tome status
        """
        enhanced = dict(seek_results)
        
        for attempt in enhanced.get('attempts', []):
            exploit_type = attempt.get('exploit_type', '')
            payload = attempt.get('payload', '')
            success = attempt.get('success', False)
            
            # Check if already in tome
            exploit_id = self._generate_exploit_id(target_url, exploit_type, payload)
            existing = self.exploit_tome.get_exploit(exploit_id)
            
            # Add payload metrics
            if payload in self.payload_service.payload_metrics:
                metrics = self.payload_service.payload_metrics[payload]
                attempt['payload_metrics'] = {
                    'execution_count': metrics.execution_count,
                    'success_rate': metrics.historical_success_rate,
                    'last_used': str(metrics.last_used)
                }
            
            # Add tome status
            attempt['in_tome'] = existing is not None
            if existing:
                attempt['tome_id'] = existing.id
                attempt['tome_success_rate'] = existing.get_success_rate()
            
            # Process into tome if successful and not already there
            if success and not existing:
                self.process_discovered_exploit(
                    target_url,
                    attempt,
                    source="seek_tab"
                )
        
        return enhanced
    
    # ========== STATISTICS & REPORTING ==========
    
    def get_integration_stats(self) -> Dict:
        """Get statistics about integrated components"""
        tome_stats = self.exploit_tome.get_statistics()
        payload_stats = self.payload_service.get_payload_statistics()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'exploit_tome': tome_stats,
            'payload_service': payload_stats,
            'active_seeks': len(self.active_seeks),
            'registered_callbacks': len(self.exploit_callbacks)
        }
    
    def get_exploit_success_rate_by_type(self) -> Dict[str, float]:
        """Get success rates for each exploit type"""
        exploits = self.exploit_tome.get_all_exploits()
        
        by_type = {}
        for exploit in exploits:
            if exploit.category not in by_type:
                by_type[exploit.category] = []
            by_type[exploit.category].append(exploit)
        
        success_rates = {}
        for exp_type, exp_list in by_type.items():
            total_success = sum(e.success_count for e in exp_list)
            total_attempts = sum(e.success_count + e.fail_count for e in exp_list)
            rate = (total_success / total_attempts * 100) if total_attempts > 0 else 0
            success_rates[exp_type] = rate
        
        return success_rates
    
    def get_recommended_payloads_for_target(self, target_url: str) -> Dict[str, List]:
        """
        Get recommended payloads based on what's worked before for similar targets
        
        Args:
            target_url: Target URL to get recommendations for
        
        Returns:
            Dict mapping exploit types to recommended payloads
        """
        # Extract domain from target
        domain = target_url.split('/')[2]
        
        # Search tome for exploits on this domain
        similar_exploits = self.exploit_tome.search_exploits(domain)
        
        recommendations = {}
        
        # Group by type and sort by success rate
        by_type = {}
        for exploit in similar_exploits:
            if exploit.category not in by_type:
                by_type[exploit.category] = []
            by_type[exploit.category].append(exploit)
        
        # Get top payloads per type
        for exp_type, exp_list in by_type.items():
            # Sort by success rate
            sorted_exploits = sorted(
                exp_list,
                key=lambda x: x.get_success_rate(),
                reverse=True
            )
            
            recommendations[exp_type] = [
                {
                    'payload': e.payload,
                    'success_rate': e.get_success_rate(),
                    'execution_count': e.success_count + e.fail_count,
                    'notes': e.notes
                }
                for e in sorted_exploits[:3]
            ]
        
        return recommendations
    
    # ========== AUTO-UPDATE MECHANISM ==========
    
    def start_auto_update_monitor(self):
        """Start background monitoring for auto-updates"""
        logger.info("Auto-update monitor started")
        # Can be called from UI thread to start periodic checks
    
    def handle_seek_completion(self, seek_result: Dict, target_url: str):
        """
        Called when seek operation completes - auto-processes all findings
        
        Args:
            seek_result: Result dict from seek operation
            target_url: Target that was tested
        """
        try:
            # Enhance with payload info
            enhanced = self.enhance_seek_results(seek_result, target_url)
            
            # Auto-add successful exploits to tome
            attempts = enhanced.get('attempts', [])
            successful = [a for a in attempts if a.get('success')]
            
            if successful:
                added_count = self.add_batch_exploits(
                    target_url,
                    successful,
                    source="seek_tab_auto"
                )
                
                logger.info(
                    f"Auto-processed {added_count} successful exploits from seek: {target_url}"
                )
                
                # Notify UI
                self._notify_callbacks({
                    'action': 'seek_completed',
                    'target': target_url,
                    'exploits_found': added_count,
                    'total_attempts': len(attempts),
                    'timestamp': datetime.now().isoformat()
                })
            
        except Exception as e:
            logger.error(f"Error handling seek completion: {e}")
            import traceback
            logger.error(traceback.format_exc())


# Convenience function for UI integration
def create_unified_integration() -> UnifiedSeekIntegration:
    """Factory function to create unified integration"""
    return UnifiedSeekIntegration()

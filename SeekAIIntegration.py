"""
SeekAIIntegration - Unified Pipeline for Exploit Seeking & AI Vulnerability Testing
Coordinates exploit discovery with AI-powered vulnerability analysis for enhanced accuracy
"""

import json
import time
import threading
import logging
from typing import Dict, List, Optional, Callable, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import traceback

logger = logging.getLogger("SeekAIIntegration")


@dataclass
class ScoredExploit:
    """Exploit with AI confidence scoring"""
    exploit_id: str
    exploit_type: str
    description: str
    payload: str
    severity: str
    confidence: float  # 0-1 exploit confidence
    ai_relevance_score: float = 0.0  # 0-1 AI-assessed relevance
    ai_success_probability: float = 0.0  # 0-1 likelihood of success
    ai_reasoning: str = ""  # Why AI thinks this exploit applies
    source: str = ""
    impact: str = ""
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)
    matched_vulnerabilities: List[str] = field(default_factory=list)  # AI vuln IDs it matches
    execution_priority: int = 1  # 1=highest, higher=lower
    
    @property
    def combined_score(self) -> float:
        """Combined exploit+AI confidence score"""
        return (self.confidence * 0.4) + (self.ai_success_probability * 0.6)


@dataclass
class VulnerabilityContext:
    """Context about target's vulnerabilities from AI analysis"""
    target_url: str
    analysis_time: float
    detected_technologies: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    weak_points: List[str] = field(default_factory=list)
    likely_vulnerabilities: List[str] = field(default_factory=list)
    defense_mechanisms: List[str] = field(default_factory=list)
    ai_observations: str = ""


@dataclass
class UnifiedResult:
    """Unified result combining exploit seeking and AI testing"""
    target: str
    timestamp: float
    seek_findings: List[ScoredExploit] = field(default_factory=list)
    ai_findings: List[Dict] = field(default_factory=list)
    context: Optional[VulnerabilityContext] = None
    correlations: List[Dict] = field(default_factory=list)  # Links between exploit & AI findings
    summary: str = ""
    
    @property
    def total_findings(self) -> int:
        return len(self.seek_findings) + len(self.ai_findings)


class SeekAIIntegration:
    """
    Unified pipeline that coordinates exploit seeking with AI vulnerability testing.
    Provides intelligent ranking, cross-learning, and result correlation.
    """
    
    def __init__(self, ai_tester=None, exploit_seeker=None, unified_seeker=None, callback: Optional[Callable] = None):
        self.ai_tester = ai_tester
        self.exploit_seeker = exploit_seeker
        self.unified_seeker = unified_seeker
        self.callback = callback  # Progress callback
        
        self.current_context: Optional[VulnerabilityContext] = None
        self.current_result: Optional[UnifiedResult] = None
        self.exploit_cache: Dict[str, ScoredExploit] = {}
        self.vulnerability_patterns: Dict[str, List[str]] = self._init_patterns()
        
    def _init_patterns(self) -> Dict[str, List[str]]:
        """Initialize vulnerability-to-exploit mapping patterns"""
        return {
            'SQL Injection': ['sql_injection', 'sql_injection_time_based', 'sql_union_select'],
            'XSS': ['xss_reflected', 'xss_stored', 'xss_dom'],
            'Authentication Bypass': ['auth_bypass', 'login_bypass', 'password_reset_bypass'],
            'CSRF': ['csrf', 'csrf_token_bypass'],
            'SSRF': ['ssrf_internal', 'ssrf_cloud_metadata'],
            'RCE': ['rce_command_injection', 'rce_code_injection', 'rce_deserialization'],
            'XXE': ['xxe_external_entity'],
            'Path Traversal': ['path_traversal', 'directory_traversal'],
            'File Upload': ['file_upload_bypass', 'file_upload_rce'],
            'Insecure Deserialization': ['insecure_deserialization'],
        }
    
    def analyze_and_score(self, target_url: str, progress_callback: Optional[Callable] = None) -> UnifiedResult:
        """
        Main pipeline: Run AI analysis and exploit seeking, then correlate & score results
        """
        self._progress(f"🔄 Starting unified analysis for {target_url}", progress_callback)
        
        result = UnifiedResult(target=target_url, timestamp=time.time())
        
        try:
            # Step 1: Run AI vulnerability analysis to get context
            self._progress("📊 Running AI vulnerability analysis...", progress_callback)
            ai_findings, context = self._run_ai_analysis(target_url, progress_callback)
            result.ai_findings = ai_findings
            result.context = context
            self.current_context = context
            
            # Step 2: Run exploit seeking (standard + unified if available)
            self._progress("🔍 Searching for applicable exploits...", progress_callback)
            exploits = self._run_exploit_seeking(target_url, progress_callback)
            
            # Step 3: Score exploits based on AI context
            self._progress("⚡ Scoring exploits against target context...", progress_callback)
            scored_exploits = self._score_exploits(exploits, context, progress_callback)
            result.seek_findings = scored_exploits
            
            # Step 4: Correlate findings across systems
            self._progress("🔗 Correlating findings across systems...", progress_callback)
            correlations = self._correlate_findings(ai_findings, scored_exploits)
            result.correlations = correlations
            
            # Step 5: Generate unified summary
            result.summary = self._generate_summary(result)
            self._progress(f"✅ Analysis complete: {result.total_findings} total findings", progress_callback)
            
            self.current_result = result
            return result
            
        except Exception as e:
            error_msg = f"Integration error: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            self._progress(f"❌ {error_msg}", progress_callback)
            raise
    
    def _run_ai_analysis(self, target_url: str, progress_callback: Optional[Callable] = None) -> Tuple[List[Dict], VulnerabilityContext]:
        """Run AI vulnerability tester and extract findings + context"""
        ai_findings = []
        context = VulnerabilityContext(target_url=target_url, analysis_time=time.time())
        
        if not self.ai_tester:
            self._progress("⚠️ AI Tester not available", progress_callback)
            return ai_findings, context
        
        try:
            # Run AI test
            result = self.ai_tester.test_website(
                target_url,
                callback=lambda msg: self._progress(f"📊 {msg}", progress_callback)
            )
            
            if result:
                ai_findings = result.get('findings', [])
                
                # Extract vulnerability context
                context.detected_technologies = result.get('detected_technologies', [])
                context.detected_frameworks = result.get('detected_frameworks', [])
                context.security_headers = result.get('security_headers', {})
                context.weak_points = result.get('weak_points', [])
                context.likely_vulnerabilities = result.get('likely_vulnerabilities', [])
                context.defense_mechanisms = result.get('defense_mechanisms', [])
                context.ai_observations = result.get('analysis_summary', '')
                
                self._progress(f"📊 AI found {len(ai_findings)} vulnerabilities", progress_callback)
        except Exception as e:
            self._progress(f"⚠️ AI analysis error: {str(e)}", progress_callback)
            logger.error(f"AI analysis error: {e}")
        
        return ai_findings, context
    
    def _run_exploit_seeking(self, target_url: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Run exploit seeking (unified > standard)"""
        exploits = []
        
        try:
            # Try unified seeker first
            if self.unified_seeker:
                self._progress("🔍 Using unified exploit knowledge...", progress_callback)
                exploits = self.unified_seeker.seek_all_exploits(target_url)
                self._progress(f"🔍 Unified seeker found {len(exploits)} exploits", progress_callback)
            
            # Fall back to standard seeker
            elif self.exploit_seeker:
                self._progress("🔍 Using standard exploit seeker...", progress_callback)
                result = self.exploit_seeker.seek_and_attempt(target_url)
                exploits = result.get('attempts', []) if result else []
                self._progress(f"🔍 Found {len(exploits)} exploit attempts", progress_callback)
            else:
                self._progress("⚠️ No exploit seeker available", progress_callback)
        
        except Exception as e:
            self._progress(f"⚠️ Exploit seeking error: {str(e)}", progress_callback)
            logger.error(f"Exploit seeking error: {e}")
        
        return exploits
    
    def _score_exploits(self, exploits: List[Dict], context: VulnerabilityContext, 
                       progress_callback: Optional[Callable] = None) -> List[ScoredExploit]:
        """
        Score exploits based on AI vulnerability context.
        Higher scores = more likely to succeed on this target.
        """
        scored = []
        
        for exploit in exploits:
            try:
                # Convert to ScoredExploit
                scored_exploit = ScoredExploit(
                    exploit_id=exploit.get('exploit_id', exploit.get('id', f'exploit_{int(time.time())}')),
                    exploit_type=exploit.get('exploit_type', exploit.get('type', 'Unknown')),
                    description=exploit.get('description', ''),
                    payload=exploit.get('payload', ''),
                    severity=exploit.get('severity', 'Medium'),
                    confidence=exploit.get('confidence', exploit.get('success', False) and 0.8 or 0.5),
                    source=exploit.get('source', 'Unknown'),
                    impact=exploit.get('impact', ''),
                    remediation=exploit.get('remediation', ''),
                )
                
                # Calculate AI relevance score
                ai_score, reasoning, matches = self._calculate_ai_relevance(
                    scored_exploit, context
                )
                scored_exploit.ai_relevance_score = ai_score
                scored_exploit.ai_success_probability = ai_score * scored_exploit.confidence
                scored_exploit.ai_reasoning = reasoning
                scored_exploit.matched_vulnerabilities = matches
                
                # Calculate execution priority (1=highest)
                scored_exploit.execution_priority = max(1, int(10 - (scored_exploit.combined_score * 10)))
                
                scored.append(scored_exploit)
            
            except Exception as e:
                logger.error(f"Error scoring exploit: {e}")
                continue
        
        # Sort by combined score (descending)
        scored.sort(key=lambda x: x.combined_score, reverse=True)
        
        # Re-assign priorities
        for i, exp in enumerate(scored, 1):
            exp.execution_priority = i
        
        return scored
    
    def _calculate_ai_relevance(self, exploit: ScoredExploit, context: VulnerabilityContext) -> Tuple[float, str, List[str]]:
        """
        Calculate how relevant this exploit is to the target based on AI analysis.
        Returns: (relevance_score, reasoning, matched_vulnerability_ids)
        """
        relevance_score = 0.5  # Base score
        reasoning_parts = []
        matched_vulns = []
        
        exploit_type_lower = exploit.exploit_type.lower()
        
        # Check against detected vulnerabilities
        for vuln in context.likely_vulnerabilities:
            vuln_lower = vuln.lower()
            
            # Direct match
            if exploit_type_lower in vuln_lower or vuln_lower in exploit_type_lower:
                relevance_score += 0.2
                reasoning_parts.append(f"Matches detected vulnerability: {vuln}")
                matched_vulns.append(vuln)
            
            # Pattern-based match
            for vuln_category, exploit_types in self._init_patterns().items():
                if any(t in exploit_type_lower for t in exploit_types):
                    if vuln_category.lower() in vuln_lower:
                        relevance_score += 0.15
                        reasoning_parts.append(f"Pattern match with {vuln_category}")
                        matched_vulns.append(vuln)
        
        # Check against weak points
        for weak_point in context.weak_points:
            weak_lower = weak_point.lower()
            if exploit_type_lower in weak_lower or weak_lower in exploit_type_lower:
                relevance_score += 0.15
                reasoning_parts.append(f"Targets weak point: {weak_point}")
        
        # Check technology compatibility
        for tech in context.detected_technologies:
            tech_lower = tech.lower()
            if tech_lower in exploit.description.lower() or tech_lower in exploit.payload.lower():
                relevance_score += 0.1
                reasoning_parts.append(f"Compatible with detected tech: {tech}")
        
        # Defense evasion bonus
        if context.defense_mechanisms:
            # Higher score if exploit might bypass known defenses
            if any(d.lower() in exploit.description.lower() for d in context.defense_mechanisms):
                relevance_score += 0.1
                reasoning_parts.append("Designed to bypass detected defenses")
        
        # Cap at 1.0
        relevance_score = min(1.0, relevance_score)
        
        reasoning = " | ".join(reasoning_parts) if reasoning_parts else "Generic exploit for target"
        
        return relevance_score, reasoning, matched_vulns
    
    def _correlate_findings(self, ai_findings: List[Dict], scored_exploits: List[ScoredExploit]) -> List[Dict]:
        """
        Create correlations between AI vulnerabilities and applicable exploits.
        Returns list of correlation objects linking related findings.
        """
        correlations = []
        
        for ai_finding in ai_findings:
            ai_vuln_type = ai_finding.get('type', ai_finding.get('title', '')).lower()
            ai_vuln_id = ai_finding.get('id', f'ai_{int(time.time())}')
            
            # Find matching exploits
            matching_exploits = []
            for exploit in scored_exploits:
                # Check if exploit is in the matched vulnerabilities list
                if ai_vuln_id in exploit.matched_vulnerabilities:
                    matching_exploits.append(exploit.exploit_id)
                
                # Also check type similarity
                if (exploit.exploit_type.lower() in ai_vuln_type or 
                    ai_vuln_type in exploit.exploit_type.lower()):
                    matching_exploits.append(exploit.exploit_id)
            
            if matching_exploits:
                correlations.append({
                    'ai_finding_id': ai_vuln_id,
                    'ai_title': ai_finding.get('title', 'Unknown'),
                    'ai_severity': ai_finding.get('severity', 'Medium'),
                    'applicable_exploits': list(set(matching_exploits)),  # Remove duplicates
                    'correlation_strength': 'direct' if len(matching_exploits) >= 2 else 'probable'
                })
        
        return correlations
    
    def _generate_summary(self, result: UnifiedResult) -> str:
        """Generate executive summary of findings"""
        summary_parts = []
        
        if not result.context:
            return "Analysis incomplete"
        
        # Summary stats
        summary_parts.append(f"Target: {result.target}")
        summary_parts.append(f"Analysis Time: {datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
        summary_parts.append("")
        
        # Technologies found
        if result.context.detected_technologies:
            summary_parts.append(f"Detected Technologies: {', '.join(result.context.detected_technologies[:5])}")
        
        # Vulnerabilities found
        summary_parts.append(f"AI Vulnerabilities Detected: {len(result.ai_findings)}")
        summary_parts.append(f"Applicable Exploits Found: {len(result.seek_findings)}")
        summary_parts.append(f"Correlated Findings: {len(result.correlations)}")
        summary_parts.append("")
        
        # Top priority exploits
        if result.seek_findings:
            top_exploits = result.seek_findings[:3]
            summary_parts.append("Top Priority Exploits:")
            for exp in top_exploits:
                summary_parts.append(f"  #{exp.execution_priority}: {exp.exploit_type} (Score: {exp.combined_score:.2f})")
        
        # Weak points
        if result.context.weak_points:
            summary_parts.append("")
            summary_parts.append(f"Identified Weak Points: {', '.join(result.context.weak_points[:3])}")
        
        return "\n".join(summary_parts)
    
    def get_ranked_exploits(self) -> List[ScoredExploit]:
        """Get exploits ranked by combined AI+exploit score"""
        if not self.current_result:
            return []
        return self.current_result.seek_findings
    
    def get_exploit_by_priority(self, priority: int) -> Optional[ScoredExploit]:
        """Get specific exploit by execution priority"""
        exploits = self.get_ranked_exploits()
        for exp in exploits:
            if exp.execution_priority == priority:
                return exp
        return None
    
    def get_findings_for_vulnerability(self, vuln_id: str) -> List[ScoredExploit]:
        """Get all exploits applicable to a specific vulnerability"""
        if not self.current_result:
            return []
        
        return [exp for exp in self.current_result.seek_findings 
                if vuln_id in exp.matched_vulnerabilities]
    
    def export_results(self, format: str = 'json') -> str:
        """Export unified results in specified format"""
        if not self.current_result:
            return ""
        
        if format == 'json':
            result_dict = {
                'target': self.current_result.target,
                'timestamp': self.current_result.timestamp,
                'summary': self.current_result.summary,
                'ai_findings': self.current_result.ai_findings,
                'scored_exploits': [asdict(exp) for exp in self.current_result.seek_findings],
                'correlations': self.current_result.correlations,
                'total_findings': self.current_result.total_findings,
            }
            return json.dumps(result_dict, indent=2, default=str)
        
        elif format == 'text':
            return self._format_text_report()
        
        return ""
    
    def _format_text_report(self) -> str:
        """Format results as detailed text report"""
        if not self.current_result:
            return ""
        
        lines = []
        result = self.current_result
        
        lines.append("=" * 80)
        lines.append("UNIFIED SECURITY ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(result.summary)
        lines.append("")
        
        # AI Findings
        if result.ai_findings:
            lines.append("=" * 80)
            lines.append("AI VULNERABILITY ANALYSIS")
            lines.append("=" * 80)
            for i, finding in enumerate(result.ai_findings, 1):
                lines.append(f"\n{i}. {finding.get('title', 'Unknown')}")
                lines.append(f"   Severity: {finding.get('severity', 'Unknown')}")
                lines.append(f"   Type: {finding.get('type', 'Unknown')}")
                lines.append(f"   Description: {finding.get('description', 'N/A')[:150]}...")
        
        # Scored Exploits
        if result.seek_findings:
            lines.append("\n" + "=" * 80)
            lines.append("RANKED EXPLOITS (by execution priority)")
            lines.append("=" * 80)
            for exp in result.seek_findings[:10]:
                lines.append(f"\n#{exp.execution_priority}: {exp.exploit_type}")
                lines.append(f"   Combined Score: {exp.combined_score:.2f}")
                lines.append(f"   AI Relevance: {exp.ai_success_probability:.2f}")
                lines.append(f"   Reasoning: {exp.ai_reasoning[:100]}...")
                if exp.matched_vulnerabilities:
                    lines.append(f"   Matches: {', '.join(exp.matched_vulnerabilities[:3])}")
        
        # Correlations
        if result.correlations:
            lines.append("\n" + "=" * 80)
            lines.append("CORRELATED FINDINGS")
            lines.append("=" * 80)
            for corr in result.correlations:
                lines.append(f"\n{corr['ai_title']} (Severity: {corr['ai_severity']})")
                lines.append(f"   Applicable Exploits: {len(corr['applicable_exploits'])}")
                lines.append(f"   Correlation: {corr['correlation_strength']}")
        
        lines.append("\n" + "=" * 80)
        
        return "\n".join(lines)
    
    def _progress(self, message: str, callback: Optional[Callable] = None):
        """Emit progress message"""
        if callback:
            callback(message)
        elif self.callback:
            self.callback(message)
        logger.info(message)

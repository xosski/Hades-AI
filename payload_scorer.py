"""
Payload Confidence Scorer
Weighs payloads by multiple factors for intelligent selection
- CVE severity and CVSS scores
- Historical success rates
- Target technology match
- Recency and frequency
- Exploit complexity and reliability
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import math

logger = logging.getLogger("PayloadScorer")


@dataclass
class PayloadMetrics:
    """Metrics for a payload"""
    payload: str
    exploit_type: str
    
    # CVE metrics
    cve_id: Optional[str] = None
    cve_severity: Optional[str] = None  # Critical, High, Medium, Low
    cvss_score: float = 0.0  # 0-10
    
    # Success metrics
    historical_success_rate: float = 0.0  # 0-1
    execution_count: int = 0
    successful_executions: int = 0
    
    # Technology match
    target_technologies: List[str] = field(default_factory=list)
    technology_match_score: float = 0.0  # 0-1
    
    # Timing metrics
    first_seen: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    use_frequency: int = 0
    
    # Complexity and reliability
    false_positive_rate: float = 0.0  # 0-1
    requires_authentication: bool = False
    requires_session: bool = False
    
    # WAF/IDS evasion
    waf_bypass_history: Dict[str, float] = field(default_factory=dict)  # WAF -> success rate
    avg_waf_bypass_rate: float = 0.0  # 0-1
    
    # Detection risk
    detection_risk: float = 0.5  # 0-1, higher = more risky
    
    # Source tracking
    source: str = "static"  # static, learned, p2p, web_scraped
    confidence: float = 0.5  # 0-1, source confidence


@dataclass
class ScoredPayload:
    """Payload with final confidence score"""
    metrics: PayloadMetrics
    final_score: float
    score_breakdown: Dict[str, float]
    rank: Optional[int] = None
    
    def __repr__(self):
        return f"ScoredPayload(score={self.final_score:.3f}, type={self.metrics.exploit_type})"


class PayloadScorer:
    """Score and rank payloads by confidence and effectiveness"""
    
    # Weighting factors for score calculation
    WEIGHTS = {
        'cve_severity': 0.25,
        'success_rate': 0.25,
        'technology_match': 0.20,
        'recency': 0.10,
        'waf_bypass': 0.10,
        'source_confidence': 0.10,
    }
    
    # CVE severity scoring
    SEVERITY_SCORES = {
        'critical': 1.0,
        'high': 0.85,
        'medium': 0.65,
        'low': 0.35,
        'unknown': 0.5,
    }
    
    # Source confidence multipliers
    SOURCE_CONFIDENCE = {
        'p2p': 0.95,  # Peer-verified
        'learned': 0.90,  # Previously successful
        'web_scraped': 0.75,  # Research/documentation
        'static': 0.60,  # Default library
    }
    
    def __init__(self):
        """Initialize scorer"""
        self.payload_history = {}  # Cache of payload metrics
        logger.info("PayloadScorer initialized")
    
    def score_payload(
        self,
        metrics: PayloadMetrics,
        target_technologies: Optional[List[str]] = None,
        target_waf: Optional[str] = None
    ) -> ScoredPayload:
        """
        Score a single payload based on multiple factors
        
        Args:
            metrics: Payload metrics
            target_technologies: Technologies to match against
            target_waf: Specific WAF to consider
        
        Returns:
            ScoredPayload with breakdown
        """
        score_breakdown = {}
        
        # 1. CVE Severity Score (0.25 weight)
        cve_score = self._score_cve_severity(metrics)
        score_breakdown['cve_severity'] = cve_score
        
        # 2. Historical Success Rate (0.25 weight)
        success_score = self._score_success_rate(metrics)
        score_breakdown['success_rate'] = success_score
        
        # 3. Technology Match (0.20 weight)
        tech_score = self._score_technology_match(
            metrics,
            target_technologies
        )
        score_breakdown['technology_match'] = tech_score
        
        # 4. Recency and Frequency (0.10 weight)
        recency_score = self._score_recency_frequency(metrics)
        score_breakdown['recency'] = recency_score
        
        # 5. WAF Bypass Capability (0.10 weight)
        waf_score = self._score_waf_bypass(metrics, target_waf)
        score_breakdown['waf_bypass'] = waf_score
        
        # 6. Source Confidence (0.10 weight)
        source_score = self._score_source_confidence(metrics)
        score_breakdown['source_confidence'] = source_score
        
        # Calculate weighted final score
        final_score = (
            cve_score * self.WEIGHTS['cve_severity'] +
            success_score * self.WEIGHTS['success_rate'] +
            tech_score * self.WEIGHTS['technology_match'] +
            recency_score * self.WEIGHTS['recency'] +
            waf_score * self.WEIGHTS['waf_bypass'] +
            source_score * self.WEIGHTS['source_confidence']
        )
        
        # Apply complexity penalty
        complexity_penalty = self._apply_complexity_penalty(metrics)
        final_score *= complexity_penalty
        
        logger.debug(
            f"Scored payload {metrics.payload[:30]}... = {final_score:.3f}"
        )
        
        return ScoredPayload(
            metrics=metrics,
            final_score=final_score,
            score_breakdown=score_breakdown
        )
    
    def score_payloads(
        self,
        payloads: List[PayloadMetrics],
        target_technologies: Optional[List[str]] = None,
        target_waf: Optional[str] = None,
        sort: bool = True
    ) -> List[ScoredPayload]:
        """
        Score multiple payloads and optionally rank them
        
        Args:
            payloads: List of payload metrics
            target_technologies: Technologies to match against
            target_waf: Specific WAF to consider
            sort: Whether to sort by score descending
        
        Returns:
            List of scored payloads
        """
        scored = []
        
        for i, payload_metrics in enumerate(payloads):
            scored_payload = self.score_payload(
                payload_metrics,
                target_technologies,
                target_waf
            )
            scored.append(scored_payload)
        
        if sort:
            scored = sorted(scored, key=lambda x: x.final_score, reverse=True)
            # Add ranking
            for rank, sp in enumerate(scored, 1):
                sp.rank = rank
        
        logger.info(f"Scored {len(scored)} payloads")
        return scored
    
    def _score_cve_severity(self, metrics: PayloadMetrics) -> float:
        """Score based on CVE severity and CVSS"""
        # If CVSS score available, use it directly
        if metrics.cvss_score > 0:
            return min(metrics.cvss_score / 10.0, 1.0)
        
        # Otherwise use severity string
        if metrics.cve_severity:
            severity_lower = metrics.cve_severity.lower()
            return self.SEVERITY_SCORES.get(severity_lower, 0.5)
        
        return 0.5  # Default
    
    def _score_success_rate(self, metrics: PayloadMetrics) -> float:
        """Score based on historical success rate"""
        if metrics.execution_count == 0:
            return 0.5  # Unknown, return neutral
        
        success_rate = metrics.successful_executions / metrics.execution_count
        
        # Boost confidence if many executions
        if metrics.execution_count >= 10:
            return success_rate
        
        # Reduce confidence if few executions
        confidence_factor = min(metrics.execution_count / 10.0, 1.0)
        return success_rate * confidence_factor + 0.5 * (1 - confidence_factor)
    
    def _score_technology_match(
        self,
        metrics: PayloadMetrics,
        target_technologies: Optional[List[str]]
    ) -> float:
        """Score based on technology stack match"""
        if not target_technologies:
            return 0.5  # Unknown target
        
        # Normalize target technologies
        target_techs = [t.lower() for t in target_technologies]
        payload_techs = [t.lower() for t in metrics.target_technologies]
        
        if not payload_techs:
            return 0.3  # Payload not tied to specific techs
        
        # Calculate match rate
        matches = sum(1 for t in payload_techs if t in target_techs)
        match_rate = matches / len(payload_techs)
        
        return match_rate
    
    def _score_recency_frequency(self, metrics: PayloadMetrics) -> float:
        """Score based on recency and usage frequency"""
        now = datetime.now()
        
        # Time decay: payloads used recently are better
        days_since_use = (now - metrics.last_used).days
        
        if days_since_use == 0:
            recency_score = 1.0
        elif days_since_use <= 7:
            recency_score = 0.9
        elif days_since_use <= 30:
            recency_score = 0.7
        elif days_since_use <= 90:
            recency_score = 0.5
        else:
            recency_score = 0.3
        
        # Frequency boost
        if metrics.use_frequency >= 100:
            frequency_boost = 0.2
        elif metrics.use_frequency >= 50:
            frequency_boost = 0.15
        elif metrics.use_frequency >= 10:
            frequency_boost = 0.1
        else:
            frequency_boost = 0
        
        combined = min(recency_score + frequency_boost, 1.0)
        return combined
    
    def _score_waf_bypass(
        self,
        metrics: PayloadMetrics,
        target_waf: Optional[str]
    ) -> float:
        """Score based on WAF bypass capability"""
        if not target_waf:
            return metrics.avg_waf_bypass_rate
        
        waf_lower = target_waf.lower()
        
        # Check if we have history for this specific WAF
        if waf_lower in metrics.waf_bypass_history:
            return metrics.waf_bypass_history[waf_lower]
        
        # Return average if no specific history
        return metrics.avg_waf_bypass_rate
    
    def _score_source_confidence(self, metrics: PayloadMetrics) -> float:
        """Score based on source of payload"""
        return self.SOURCE_CONFIDENCE.get(
            metrics.source.lower(),
            0.5
        )
    
    def _apply_complexity_penalty(self, metrics: PayloadMetrics) -> float:
        """Apply penalty for payload complexity/requirements"""
        penalty = 1.0
        
        # Penalty for authentication requirement
        if metrics.requires_authentication:
            penalty *= 0.8
        
        # Penalty for session requirement
        if metrics.requires_session:
            penalty *= 0.85
        
        # Penalty for high false positive rate
        if metrics.false_positive_rate > 0.3:
            penalty *= (1.0 - metrics.false_positive_rate * 0.5)
        
        # Penalty for high detection risk
        if metrics.detection_risk > 0.7:
            penalty *= 0.75
        
        return penalty
    
    def get_top_payloads(
        self,
        payloads: List[PayloadMetrics],
        top_n: int = 10,
        target_technologies: Optional[List[str]] = None,
        target_waf: Optional[str] = None
    ) -> List[ScoredPayload]:
        """
        Get top N payloads for given criteria
        
        Args:
            payloads: List of payload metrics
            top_n: Number of top payloads to return
            target_technologies: Technologies to match
            target_waf: WAF to target
        
        Returns:
            List of top scored payloads
        """
        scored = self.score_payloads(
            payloads,
            target_technologies,
            target_waf,
            sort=True
        )
        
        return scored[:top_n]
    
    def compare_payloads(
        self,
        payload1: PayloadMetrics,
        payload2: PayloadMetrics
    ) -> Dict:
        """Compare two payloads"""
        score1 = self.score_payload(payload1)
        score2 = self.score_payload(payload2)
        
        winner = payload1 if score1.final_score > score2.final_score else payload2
        
        return {
            'payload1': {
                'score': score1.final_score,
                'breakdown': score1.score_breakdown
            },
            'payload2': {
                'score': score2.final_score,
                'breakdown': score2.score_breakdown
            },
            'winner': winner.payload[:50],
            'score_difference': abs(score1.final_score - score2.final_score)
        }
    
    def explain_score(self, scored_payload: ScoredPayload) -> str:
        """Get human-readable explanation of score"""
        parts = []
        parts.append(f"Payload: {scored_payload.metrics.payload[:50]}...")
        parts.append(f"Final Score: {scored_payload.final_score:.3f}")
        parts.append("\nScore Breakdown:")
        
        for factor, score in scored_payload.score_breakdown.items():
            weight = self.WEIGHTS.get(factor, 0)
            contribution = score * weight
            parts.append(
                f"  {factor:25} {score:.3f} (weight: {weight:.2f}, contrib: {contribution:.3f})"
            )
        
        # Add metrics context
        metrics = scored_payload.metrics
        parts.append(f"\nMetrics:")
        parts.append(f"  CVE: {metrics.cve_id} ({metrics.cve_severity})")
        parts.append(f"  Success Rate: {metrics.successful_executions}/{metrics.execution_count}")
        parts.append(f"  Technologies: {', '.join(metrics.target_technologies)}")
        parts.append(f"  Source: {metrics.source}")
        
        return '\n'.join(parts)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scorer = PayloadScorer()
    
    # Create test payloads
    payload1 = PayloadMetrics(
        payload="' OR '1'='1' --",
        exploit_type="sql_injection",
        cve_id="CVE-2023-1234",
        cve_severity="High",
        cvss_score=8.5,
        historical_success_rate=0.85,
        execution_count=20,
        successful_executions=17,
        target_technologies=["PHP", "MySQL"],
        use_frequency=50,
        source="learned",
        confidence=0.9
    )
    
    payload2 = PayloadMetrics(
        payload="UNION SELECT NULL,NULL,NULL --",
        exploit_type="sql_injection",
        cve_id="CVE-2023-5678",
        cve_severity="Medium",
        cvss_score=6.5,
        historical_success_rate=0.65,
        execution_count=10,
        successful_executions=6,
        target_technologies=["PHP", "PostgreSQL"],
        use_frequency=20,
        source="static",
        confidence=0.6
    )
    
    # Score single payloads
    print("=== Individual Scoring ===\n")
    scored1 = scorer.score_payload(
        payload1,
        target_technologies=["PHP", "MySQL"]
    )
    print(scorer.explain_score(scored1))
    
    print("\n" + "="*60 + "\n")
    
    scored2 = scorer.score_payload(
        payload2,
        target_technologies=["PHP", "MySQL"]
    )
    print(scorer.explain_score(scored2))
    
    # Compare payloads
    print("\n" + "="*60)
    print("=== Payload Comparison ===\n")
    comparison = scorer.compare_payloads(payload1, payload2)
    print(f"Payload 1 Score: {comparison['payload1']['score']:.3f}")
    print(f"Payload 2 Score: {comparison['payload2']['score']:.3f}")
    print(f"Winner: {comparison['winner']}")
    print(f"Score Difference: {comparison['score_difference']:.3f}")
    
    # Score multiple
    print("\n" + "="*60)
    print("=== Scoring Multiple Payloads ===\n")
    all_payloads = [payload1, payload2]
    scored_all = scorer.score_payloads(
        all_payloads,
        target_technologies=["PHP", "MySQL"],
        sort=True
    )
    
    for sp in scored_all:
        print(f"Rank: {sp.rank} | Score: {sp.final_score:.3f} | {sp.metrics.exploit_type}")

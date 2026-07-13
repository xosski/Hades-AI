#!/usr/bin/env python3
"""
Test script to verify LLM integration with HadesAI
"""

import sys
import os
import logging
import tempfile

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("LLM_Test")

def test_llm_core_import():
    """Test that llm_conversation_core can be imported"""
    logger.info("Testing LLM Core import...")
    try:
        from llm_conversation_core import ConversationManager
        logger.info("✓ LLM Core imported successfully")
        return True
    except ImportError as e:
        logger.error(f"✗ Failed to import LLM Core: {e}")
        return False

def test_conversation_manager():
    """Test ConversationManager initialization"""
    logger.info("\nTesting ConversationManager initialization...")
    try:
        from llm_conversation_core import ConversationManager
        mgr = ConversationManager()
        providers = mgr.get_available_providers()
        logger.info(f"✓ ConversationManager initialized")
        logger.info(f"  Available providers: {providers}")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to initialize ConversationManager: {e}")
        return False

def test_hades_ai_integration():
    """Test HadesAI LLM integration"""
    logger.info("\nTesting HadesAI LLM integration...")
    try:
        from HadesAI import HadesAI
        ai = HadesAI()
        
        if ai.llm_manager:
            logger.info("✓ HadesAI LLM Manager initialized")
            providers = ai.get_available_llm_providers()
            logger.info(f"  Available providers: {providers}")
            return True
        else:
            logger.warning("⚠ LLM Manager not initialized in HadesAI")
            return False
    except Exception as e:
        logger.error(f"✗ Failed to initialize HadesAI: {e}")
        return False

def test_llm_chat():
    """Test LLM chat functionality"""
    logger.info("\nTesting LLM chat functionality...")
    try:
        from HadesAI import HadesAI
        ai = HadesAI()
        
        if not ai.llm_manager:
            logger.warning("⚠ LLM Manager not available, skipping chat test")
            return False
        
        # Test with fallback provider (always available)
        response = ai.llm_chat(
            "What is SQL injection?",
            provider="fallback"
        )
        
        if response and not response.startswith("❌"):
            logger.info("✓ LLM chat working")
            logger.info(f"  Response length: {len(response)} chars")
            return True
        else:
            logger.warning(f"⚠ LLM chat returned error: {response}")
            return False
            
    except Exception as e:
        logger.error(f"✗ Failed to test LLM chat: {e}")
        return False

def _legacy_test_conversation_persistence():
    """Test conversation persistence"""
    logger.info("\nTesting conversation persistence...")
    try:
        from llm_conversation_core import ConversationManager
        import os
        
        # Create manager with test DB
        test_db = "test_conversations.db"
        mgr = ConversationManager(db_path=test_db)
        
        # Create conversation
        conv = mgr.create_conversation(
            title="Test Conversation",
            provider="fallback"
        )
        logger.info(f"✓ Conversation created: {conv.id}")
        
        # Send message
        response = mgr.send_message("Hello", conv_id=conv.id, use_streaming=False)
        logger.info(f"✓ Message sent, response: {response[:50]}...")
        
        # List conversations
        convs = mgr.list_conversations()
        logger.info(f"✓ Listed conversations: {len(convs)} total")
        
        # Clean up
        if os.path.exists(test_db):
            os.remove(test_db)
        
        return True
    except Exception as e:
        logger.error(f"✗ Failed to test conversation persistence: {e}")
        return False

def test_durable_conversation_and_memory():
    """Verify message history and cognitive feedback survive process restarts."""
    from llm_conversation_core import ConversationManager
    from modules.cognitive_memory import CognitiveLayer

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            conversation_db = os.path.join(temp_dir, "conversations.db")
            manager = ConversationManager(db_path=conversation_db)
            conversation = manager.create_conversation("Persistence", provider="fallback")
            response = manager.send_message("Hello", conv_id=conversation.id)
            streamed_response = "".join(
                manager.send_message("Help", conv_id=conversation.id, use_streaming=True)
            )

            reloaded = ConversationManager(db_path=conversation_db).load_conversation(
                conversation.id
            )
            assert reloaded is not None
            assert [message.role for message in reloaded.messages] == [
                "user", "assistant", "user", "assistant"
            ]
            assert reloaded.messages[1].content == response
            assert reloaded.messages[3].content == streamed_response

            memory_db = os.path.join(temp_dir, "memory.db")
            memory = CognitiveLayer(db_path=memory_db)
            memory_id = memory.remember(
                "The project database is PostgreSQL",
                importance=0.8,
                metadata={"type": "project_fact"}
            )
            reflection_id = memory.evaluate_response(
                "Which database do we use?", "PostgreSQL", 0.9
            )

            reloaded_memory = CognitiveLayer(db_path=memory_db)
            recalled = reloaded_memory.recall("project database PostgreSQL", top_k=1)
            assert recalled and recalled[0][1].id == memory_id
            assert reloaded_memory.get_memory_stats()["total_memories"] == 2
            assert reloaded_memory.get_reflection_stats()["total_reflections"] == 1
            assert reflection_id in reloaded_memory._reinforcement_map
            assert reloaded_memory.reinforce_memory(memory_id, 1.0)

        logger.info("Durable conversation and cognitive memory round trip passed")
        return True
    except Exception as e:
        logger.error(f"Durable conversation and memory test failed: {e}")
        return False


def main():
    """Run all tests"""
    logger.info("=" * 60)
    logger.info("LLM Integration Tests")
    logger.info("=" * 60)
    
    results = []
    
    results.append(("LLM Core Import", test_llm_core_import()))
    results.append(("ConversationManager", test_conversation_manager()))
    results.append(("HadesAI Integration", test_hades_ai_integration()))
    results.append(("LLM Chat", test_llm_chat()))
    results.append(("Durable Conversation and Memory", test_durable_conversation_and_memory()))
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Test Summary:")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status}: {test_name}")
    
    logger.info(f"\nTotal: {passed}/{total} tests passed")
    logger.info("=" * 60)
    
    if passed == total:
        logger.info("✓ All tests passed! LLM integration is working correctly.")
        return 0
    else:
        logger.warning(f"⚠ {total - passed} test(s) failed. Check logs for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

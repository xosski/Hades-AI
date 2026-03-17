"""
Hades AI LLM - Usage Examples
Demonstrates all major features and use cases
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from llm_conversation_core import ConversationManager, LLMProvider


def example_1_basic_conversation():
    """Example 1: Basic conversation with automatic provider selection"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Conversation")
    print("="*60)
    
    manager = ConversationManager()
    
    # Create conversation
    conv = manager.create_conversation(
        title="Security Tips",
        provider="openai",  # Will fallback if unavailable
    )
    
    print(f"Created: {conv.title}")
    print(f"Provider: {conv.provider}")
    
    # Send messages
    messages = [
        "What are the top 5 security best practices?",
        "Explain OWASP Top 10",
        "How do I implement rate limiting?"
    ]
    
    for msg in messages:
        print(f"\nYou: {msg}")
        response = manager.send_message(msg, conv_id=conv.id)
        print(f"AI: {response[:200]}...")


def example_2_streaming():
    """Example 2: Real-time streaming responses"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Streaming Responses")
    print("="*60)
    
    manager = ConversationManager()
    
    conv = manager.create_conversation(
        title="Code Analysis",
        provider="ollama",  # Local for faster response
    )
    
    prompt = "Explain how SQL injection works in 3 paragraphs"
    print(f"\nPrompt: {prompt}\n")
    print("Streaming response:\n")
    
    full_response = ""
    for chunk in manager.send_message(prompt, conv_id=conv.id, use_streaming=True):
        print(chunk, end="", flush=True)
        full_response += chunk
    
    print("\n\n[Stream complete]")


def example_3_provider_switching():
    """Example 3: Switch providers mid-conversation"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Provider Switching")
    print("="*60)
    
    manager = ConversationManager()
    
    # Create with OpenAI
    conv = manager.create_conversation(
        title="Multi-Provider Test",
        provider="openai"
    )
    
    print(f"Initial provider: {conv.provider}")
    
    # Send message
    response1 = manager.send_message(
        "What is cryptography?",
        conv_id=conv.id
    )
    print(f"OpenAI response: {response1[:100]}...\n")
    
    # Switch to Mistral
    if manager.switch_provider(conv.id, "mistral", "mistral-tiny"):
        print("Switched to Mistral")
        response2 = manager.send_message(
            "Explain the same concept again",
            conv_id=conv.id
        )
        print(f"Mistral response: {response2[:100]}...\n")
    
    # Show available providers
    print(f"Available providers: {manager.get_available_providers()}")


def example_4_system_prompts():
    """Example 4: Using system prompts for specialized assistants"""
    print("\n" + "="*60)
    print("EXAMPLE 4: System Prompts for Specialization")
    print("="*60)
    
    manager = ConversationManager()
    
    # Security Analyst Bot
    security_conv = manager.create_conversation(
        title="Security Analyst",
        system_prompt="""You are an expert security analyst with 10+ years experience.
        Your responses should:
        - Focus on security implications
        - Provide concrete recommendations
        - Reference OWASP/CVE standards
        - Suggest defensive measures"""
    )
    
    # Code Reviewer Bot
    code_conv = manager.create_conversation(
        title="Code Reviewer",
        system_prompt="""You are an expert code reviewer.
        Analyze code for:
        - Performance issues
        - Memory leaks
        - Security vulnerabilities
        - Code style and best practices"""
    )
    
    # Test with same question
    question = "Review this authentication code: if password == stored_password: login()"
    
    print(f"\nQuestion: {question}\n")
    
    print("Security Analyst perspective:")
    response1 = manager.send_message(question, conv_id=security_conv.id)
    print(f"  {response1[:200]}...\n")
    
    print("Code Reviewer perspective:")
    response2 = manager.send_message(question, conv_id=code_conv.id)
    print(f"  {response2[:200]}...\n")


def example_5_conversation_history():
    """Example 5: Manage conversation history"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Conversation History Management")
    print("="*60)
    
    manager = ConversationManager()
    
    # Create conversation
    conv = manager.create_conversation(title="Multi-turn Conversation")
    
    # Multi-turn conversation
    exchanges = [
        ("What is JWT?", "JWT is a stateless authentication token format..."),
        ("How is it different from sessions?", "JWTs are self-contained while sessions..."),
        ("When should I use each?", "Use JWT for microservices, sessions for monoliths..."),
    ]
    
    print(f"Conversation ID: {conv.id}\n")
    
    for user_msg, _ in exchanges:
        print(f"You: {user_msg}")
        response = manager.send_message(user_msg, conv_id=conv.id)
        print(f"AI: {response[:150]}...\n")
    
    # Load and display history
    print("Conversation History:")
    loaded_conv = manager.load_conversation(conv.id)
    
    for i, msg in enumerate(loaded_conv.messages, 1):
        role = msg.role.upper()
        preview = msg.content[:80] + "..." if len(msg.content) > 80 else msg.content
        print(f"  [{i}] {role}: {preview}")
    
    # Export
    export_data = {
        "id": loaded_conv.id,
        "title": loaded_conv.title,
        "message_count": len(loaded_conv.messages),
        "provider": loaded_conv.provider,
    }
    print(f"\nExport ready: {export_data}")


def example_6_temperature_control():
    """Example 6: Control creativity with temperature"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Temperature Control (Creativity)")
    print("="*60)
    
    manager = ConversationManager()
    
    temps = [
        (0.1, "Focused/Deterministic", "What is 2+2?"),
        (0.7, "Balanced", "Write a haiku about security"),
        (0.95, "Creative/Random", "Invent a fictional programming language"),
    ]
    
    for temp, description, prompt in temps:
        conv = manager.create_conversation(
            title=f"Temp {temp} Test",
            temperature=temp
        )
        
        print(f"\nTemperature: {temp} ({description})")
        print(f"Prompt: {prompt}")
        
        response = manager.send_message(prompt, conv_id=conv.id)
        print(f"Response: {response[:100]}...\n")


def example_7_list_and_manage():
    """Example 7: List and manage conversations"""
    print("\n" + "="*60)
    print("EXAMPLE 7: List & Manage Conversations")
    print("="*60)
    
    manager = ConversationManager()
    
    # Create several conversations
    for i in range(3):
        manager.create_conversation(
            title=f"Test Conversation {i+1}",
            provider="openai"
        )
    
    # List all
    convs = manager.list_conversations(limit=10)
    print(f"Total conversations: {len(convs)}\n")
    
    for conv in convs[:5]:  # Show first 5
        print(f"Title: {conv['title']}")
        print(f"  ID: {conv['id'][:16]}...")
        print(f"  Provider: {conv['provider']}")
        print(f"  Updated: {conv['updated_at']}\n")


def example_8_error_handling():
    """Example 8: Error handling and fallback"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Error Handling & Fallback")
    print("="*60)
    
    manager = ConversationManager()
    
    # Try non-existent conversation
    result = manager.load_conversation("nonexistent_id_12345")
    print(f"Load non-existent: {result}")
    
    # Create with invalid provider (should fallback)
    conv = manager.create_conversation(
        title="Fallback Test",
        provider="nonexistent_provider"
    )
    print(f"\nCreated with invalid provider: {conv.provider}")
    
    # Send message (should use fallback)
    response = manager.send_message(
        "Hello, what's your name?",
        conv_id=conv.id
    )
    print(f"Response from fallback: {response}")
    
    # Test with intentionally broken provider
    available = manager.get_available_providers()
    print(f"\nAvailable providers: {available}")


def example_9_batch_processing():
    """Example 9: Batch process multiple requests"""
    print("\n" + "="*60)
    print("EXAMPLE 9: Batch Processing")
    print("="*60)
    
    manager = ConversationManager()
    
    # Create conversation for batch processing
    conv = manager.create_conversation(
        title="Batch Analysis",
        max_tokens=500  # Shorter responses for batch
    )
    
    vulnerabilities = [
        "SELECT * FROM users WHERE id = " + request_param,
        "eval(user_input)",
        "<img src=x onerror='alert(1)'>",
    ]
    
    print(f"Analyzing {len(vulnerabilities)} items...\n")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        prompt = f"What security issue is in this code: {vuln}"
        response = manager.send_message(prompt, conv_id=conv.id)
        print(f"{i}. {response[:100]}...")


def example_10_integration():
    """Example 10: Integration with Hades AI"""
    print("\n" + "="*60)
    print("EXAMPLE 10: Integration with Hades AI")
    print("="*60)
    
    print("""
Example integration code:

# In HadesAI.py exploit analysis:
from llm_conversation_core import ConversationManager

conv_manager = ConversationManager()

# Create analysis conversation
conv = conv_manager.create_conversation(
    title="Exploit Analysis",
    system_prompt=\"\"\"You are an expert in security exploitation.
    Analyze and explain exploits, including:
    - How the vulnerability works
    - Attack vectors
    - Impact assessment
    - Remediation strategies\"\"\"
)

# Analyze vulnerabilities
vulnerable_code = get_vulnerable_code()
analysis = conv_manager.send_message(
    f"Analyze this vulnerability: {vulnerable_code}",
    conv_id=conv.id
)

# Use streaming for real-time output in GUI
for chunk in conv_manager.send_message(
    prompt,
    conv_id=conv.id,
    use_streaming=True
):
    emit_to_gui(chunk)
    """)


def run_all_examples():
    """Run all examples"""
    examples = [
        example_1_basic_conversation,
        example_2_streaming,
        example_3_provider_switching,
        example_4_system_prompts,
        example_5_conversation_history,
        example_6_temperature_control,
        example_7_list_and_manage,
        example_8_error_handling,
        example_9_batch_processing,
        example_10_integration,
    ]
    
    print("\n" + "🔥"*30)
    print("HADES AI LLM - EXAMPLES")
    print("🔥"*30)
    
    for example_func in examples:
        try:
            example_func()
        except Exception as e:
            print(f"\n❌ Error in {example_func.__name__}: {str(e)}")
        
        input("\nPress Enter to continue to next example...")
    
    print("\n" + "="*60)
    print("✨ All examples complete!")
    print("="*60)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    if len(sys.argv) > 1:
        # Run specific example
        example_num = int(sys.argv[1])
        examples = [
            example_1_basic_conversation,
            example_2_streaming,
            example_3_provider_switching,
            example_4_system_prompts,
            example_5_conversation_history,
            example_6_temperature_control,
            example_7_list_and_manage,
            example_8_error_handling,
            example_9_batch_processing,
            example_10_integration,
        ]
        if 0 < example_num <= len(examples):
            examples[example_num - 1]()
    else:
        # Interactive menu
        print("\n" + "="*60)
        print("HADES AI LLM - EXAMPLES MENU")
        print("="*60)
        print("1. Basic conversation")
        print("2. Streaming responses")
        print("3. Provider switching")
        print("4. System prompts")
        print("5. Conversation history")
        print("6. Temperature control")
        print("7. List & manage")
        print("8. Error handling")
        print("9. Batch processing")
        print("10. Integration")
        print("11. Run all examples")
        print("0. Exit")
        
        choice = input("\nSelect example (0-11): ").strip()
        
        if choice == "11":
            run_all_examples()
        elif choice in "0123456789":
            num = int(choice)
            if num == 0:
                sys.exit(0)
            examples = [
                None,
                example_1_basic_conversation,
                example_2_streaming,
                example_3_provider_switching,
                example_4_system_prompts,
                example_5_conversation_history,
                example_6_temperature_control,
                example_7_list_and_manage,
                example_8_error_handling,
                example_9_batch_processing,
                example_10_integration,
            ]
            if examples[num]:
                examples[num]()

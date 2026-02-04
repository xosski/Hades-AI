#!/usr/bin/env python3
"""
Test script demonstrating sophisticated response generation
Shows before/after comparison and different response types
"""

from modules.sophisticated_responses import SophisticatedResponseEngine
from modules.advanced_response_formatter import AdvancedResponseFormatter, ResponseStyle

def print_section(title: str, content: str):
    """Print a formatted section"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")
    print(content)


def test_basic_thinking():
    """Test basic thinking process generation"""
    engine = SophisticatedResponseEngine()
    
    queries = [
        "How does SQL injection work?",
        "Explain privilege escalation techniques",
        "What's the best way to secure an API?"
    ]
    
    for query in queries:
        print_section(f"Thinking Process: {query}", 
                     engine.generate_thinking_process(query))


def test_different_styles():
    """Test different response styles"""
    engine = SophisticatedResponseEngine()
    brain_state = {"mood": "analytical"}
    
    test_queries = {
        "technical": "Explain ASLR bypass techniques",
        "educational": "Teach me how buffer overflows work",
        "strategic": "What's the best approach to secure our system?",
        "analytical": "Analyze the security risks in a monolithic architecture"
    }
    
    for response_type, query in test_queries.items():
        print_section(f"Response Type: {response_type.upper()}", 
                     query + "\n\n" + engine.synthesize_response(brain_state, query)[:500] + "...[truncated]")


def test_formatter():
    """Test advanced response formatter"""
    formatter = AdvancedResponseFormatter()
    
    test_content = """
    SQL Injection is a web application vulnerability that allows attackers to interfere with database queries.
    
    **Attack Vector:**
    An attacker can inject malicious SQL code through user input fields that are improperly sanitized.
    
    **Impact:**
    - Unauthorized data access
    - Data modification or deletion
    - Authentication bypass
    - Remote code execution
    
    **Prevention:**
    Use parameterized queries, input validation, and the principle of least privilege.
    """
    
    formatted = formatter.format_with_thinking(
        user_input="Explain SQL injection",
        response_content=test_content,
        thinking_process="Analyzing security query at intermediate level...",
        style=ResponseStyle.TECHNICAL
    )
    
    print_section("Advanced Response Formatter Output", formatted)


def test_sophistication_levels():
    """Test response adjustment based on sophistication level"""
    engine = SophisticatedResponseEngine()
    
    # Simple query
    simple_brain = {"mood": "neutral"}
    simple_query = "What is security?"
    
    # Complex query
    complex_brain = {"mood": "analytical"}
    complex_query = "Explain zero-day CVE exploitation chains and ASLR bypass techniques"
    
    print_section("Simple Query Response", 
                 engine.synthesize_response(simple_brain, simple_query)[:400] + "...")
    
    print_section("Complex Query Response", 
                 engine.synthesize_response(complex_brain, complex_query)[:400] + "...")


def test_concept_extraction():
    """Test automatic concept extraction"""
    engine = SophisticatedResponseEngine()
    
    test_queries = [
        "Tell me about SQL injection vulnerabilities",
        "How do I set up network encryption?",
        "Explain authentication and authorization",
        "What are API security best practices?"
    ]
    
    for query in test_queries:
        concepts = engine._extract_concepts(query)
        print(f"Query: {query}")
        print(f"Extracted Concepts: {concepts}\n")


def test_reasoning_markers():
    """Show reasoning marker variations"""
    engine = SophisticatedResponseEngine()
    
    print_section("Reasoning Markers (Used in Responses)", 
                 "\n".join(engine.reasoning_markers))


def test_context_analysis():
    """Test context analysis for query type detection"""
    engine = SophisticatedResponseEngine()
    
    test_cases = [
        ("What is XSS?", "neutral"),
        ("How do I fix vulnerabilities?", "optimistic"),
        ("Explain exploit chains", "curious"),
        ("Design a secure architecture", "analytical"),
    ]
    
    print("\nContext Analysis Results:")
    print("-" * 80)
    
    for query, mood in test_cases:
        brain_state = {"mood": mood}
        mood_result, complexity, request_type = engine.analyze_context(brain_state, query)
        print(f"Query: {query}")
        print(f"  Detected Mood: {mood_result}")
        print(f"  Complexity: {complexity}")
        print(f"  Request Type: {request_type}\n")


def test_full_workflow():
    """Test complete workflow from query to formatted response"""
    engine = SophisticatedResponseEngine()
    formatter = AdvancedResponseFormatter()
    
    user_query = "How should we approach securing our microservices architecture?"
    
    # Analyze context
    brain_state = {"mood": "analytical"}
    mood, complexity, request_type = engine.analyze_context(brain_state, user_query)
    
    # Generate response
    response_content = """
    Securing a microservices architecture requires a multi-layered approach:
    
    **Network Level:**
    - Service mesh with mTLS
    - Network policies and segmentation
    - API gateways with authentication
    
    **Application Level:**
    - Secure coding practices
    - Input validation
    - Rate limiting and DDoS protection
    
    **Data Level:**
    - Encryption at rest and in transit
    - Secrets management
    - Audit logging
    """
    
    # Format output
    formatted = formatter.format_with_thinking(
        user_input=user_query,
        response_content=response_content,
        thinking_process=engine.generate_thinking_process(user_query),
        style=ResponseStyle.STRATEGIC
    )
    
    print_section("Full Workflow: Query to Formatted Response", formatted)


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("  SOPHISTICATED RESPONSE ENGINE TEST SUITE")
    print("="*80)
    
    print("\n1. Testing Thinking Process Generation")
    test_basic_thinking()
    
    print("\n2. Testing Different Response Styles")
    test_different_styles()
    
    print("\n3. Testing Advanced Formatter")
    test_formatter()
    
    print("\n4. Testing Sophistication Levels")
    test_sophistication_levels()
    
    print("\n5. Testing Concept Extraction")
    test_concept_extraction()
    
    print("\n6. Testing Reasoning Markers")
    test_reasoning_markers()
    
    print("\n7. Testing Context Analysis")
    test_context_analysis()
    
    print("\n8. Testing Full Workflow")
    test_full_workflow()
    
    print("\n" + "="*80)
    print("  TEST SUITE COMPLETE")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()

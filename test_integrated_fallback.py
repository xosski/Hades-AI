#!/usr/bin/env python3
"""Integrated test of fallback LLM systems working together"""

try:
    from fallback_llm import FallbackLLM
    from exploit_generator_multi_llm import FallbackLLMProvider
    
    print("[*] INTEGRATED FALLBACK LLM TEST")
    print("=" * 60)
    
    # Initialize both systems
    agent_llm = FallbackLLM()
    exploit_provider = FallbackLLMProvider()
    
    print("\n[1] AUTONOMOUS AGENT PLANNING PHASE")
    print("-" * 60)
    
    # Agent gets a goal
    system_prompt = "You are a code analyst. Provide a short high-level plan."
    user_prompt = "Goals: Find security vulnerabilities in Python code"
    
    plan_response = agent_llm(system_prompt, user_prompt)
    plan_json = eval(plan_response)  # Safe here for testing
    print(f"Goal Type: {agent_llm._classify_goal('Find security vulnerabilities')}")
    print(f"Plan Steps:\n{plan_json['plan']}")
    
    print("\n[2] ACTION DECISION PHASE")
    print("-" * 60)
    
    # Agent decides what action to take
    system_prompt = "Choose ONE next action to execute"
    user_prompt = """Goals: Find security vulnerabilities in Python code
    Observations: Found socket imports, buffer operations, and SQL queries
    Recent steps: Listed files, read main.py"""
    
    action_response = agent_llm(system_prompt, user_prompt)
    action_json = eval(action_response)
    print(f"Next Action: {action_json['tool']}")
    print(f"Rationale: {action_json['rationale']}")
    
    print("\n[3] VULNERABILITY ANALYSIS")
    print("-" * 60)
    
    # Simulate analysis finding vulnerabilities
    analysis_results = [
        "Found SQL injection vulnerability in database.query() method",
        "Detected buffer overflow in C extension sprintf() call",
        "XSS vulnerability in template rendering with eval()",
        "Command injection via os.system() with user input",
    ]
    
    for analysis in analysis_results:
        vuln_type = exploit_provider._detect_vulnerability_type(analysis)
        print(f"[*] Analysis: {analysis}")
        print(f"    Type: {vuln_type}")
    
    print("\n[4] EXPLOIT GENERATION PHASE")
    print("-" * 60)
    
    # For each vulnerability, generate an exploit
    for analysis in analysis_results:
        vuln_type = exploit_provider._detect_vulnerability_type(analysis)
        exploit = exploit_provider.generate(analysis)
        
        # Show preview
        lines = exploit.split('\n')
        preview = '\n'.join(lines[:5])
        
        print(f"\n[+] {vuln_type.upper()} Exploit Generated")
        print(f"    Size: {len(exploit)} bytes")
        print(f"    Preview:\n{preview}...")
    
    print("\n[5] REFLECTION AND PLANNING UPDATE")
    print("-" * 60)
    
    # Agent reflects on what happened
    system_prompt = "Update and trim the plan based on observations"
    user_prompt = """Observations: Successfully identified and generated exploits for 4 vulnerabilities
    Recent steps: Analyzed code, detected patterns, generated POCs"""
    
    reflection = agent_llm(system_prompt, user_prompt)
    try:
        reflection_json = eval(reflection)
        updated_plan = reflection_json.get('updated_plan', reflection_json.get('plan', reflection))
    except:
        updated_plan = reflection
    print(f"Updated Plan: {updated_plan}")
    
    print("\n" + "=" * 60)
    print("[SUCCESS] Integrated fallback LLM system working perfectly!")
    print("=" * 60)
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

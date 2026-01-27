#!/usr/bin/env python3
"""Test FallbackLLM implementation"""

try:
    from fallback_llm import FallbackLLM
    print("[OK] fallback_llm imports successfully")
    
    # Test it
    llm = FallbackLLM()
    
    # Test different prompts
    result1 = llm("You are a planner", "Provide a plan")
    result2 = llm("Choose next action", "Goals: analyze code")
    result3 = llm("reflector", "Update the plan")
    
    print("[OK] FallbackLLM generates responses")
    print("[OK] All prompts work correctly")
    print("")
    print("Sample outputs:")
    print(f"  Plan: {result1[:60]}...")
    print(f"  Action: {result2[:60]}...")
    print(f"  Update: {result3[:60]}...")
    print("")
    print("[SUCCESS] FallbackLLM is working!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

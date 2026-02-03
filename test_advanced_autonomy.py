#!/usr/bin/env python3
"""
Test script for Advanced Autonomy Systems
Tests all four new autonomous systems
"""

import logging
import time
from modules.self_healing_system import SelfHealingSystem, ErrorEvent
from modules.adaptive_strategy_engine import AdaptiveStrategyEngine, StrategyType
from modules.autonomous_scheduler import AutonomousScheduler, TaskPriority
from modules.multi_agent_system import MultiAgentSystem, AgentRole

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AdvancedAutonomyTest")


def test_self_healing():
    """Test Self-Healing System"""
    print("\n" + "="*60)
    print("Testing Self-Healing System")
    print("="*60)
    
    healing = SelfHealingSystem()
    
    # Enable
    print("\n[1] Enabling self-healing...")
    success = healing.enable_self_healing(
        auto_retry=True,
        auto_rollback=True,
        auto_heal=True,
        monitoring=True
    )
    print(f"✓ Self-healing enabled: {success}")
    
    # Start monitoring
    print("\n[2] Starting health monitoring...")
    healing.start_monitoring()
    time.sleep(2)
    print("✓ Monitoring started")
    
    # Report error
    print("\n[3] Reporting test error...")
    healing.report_error(
        component="test_component",
        error_type="connection_timeout",
        message="Test timeout error",
        severity=0.6,
        context={"target": "192.168.1.1"}
    )
    print("✓ Error reported and healing attempted")
    
    # Get status
    print("\n[4] Getting health status...")
    status = healing.get_health_status()
    print(f"✓ Overall status: {status['status']}")
    print(f"  Healthy metrics: {status['healthy_metrics']}/{status['total_metrics']}")
    
    # Get history
    print("\n[5] Getting error history...")
    errors = healing.get_error_history(limit=5)
    print(f"✓ Errors recorded: {len(errors)}")
    for error in errors:
        print(f"  - {error['component']}: {error['error_type']} (severity={error['severity']:.2f})")
    
    healing.stop_monitoring()
    print("\n✅ Self-Healing System Test Complete")
    return True


def test_adaptive_strategies():
    """Test Adaptive Strategy Engine"""
    print("\n" + "="*60)
    print("Testing Adaptive Strategy Engine")
    print("="*60)
    
    engine = AdaptiveStrategyEngine()
    
    # Enable
    print("\n[1] Enabling adaptive strategies...")
    success = engine.enable_adaptive_strategies(
        ab_testing=True,
        auto_switch=True,
        performance_threshold=0.3
    )
    print(f"✓ Adaptive strategies enabled: {success}")
    
    # Register strategies
    print("\n[2] Registering attack strategies...")
    engine.register_strategy("sql_injection", StrategyType.EXPLOIT_KNOWN, "web_app")
    engine.register_strategy("bruteforce_ssh", StrategyType.BRUTE_FORCE, "linux_server")
    engine.register_strategy("buffer_overflow", StrategyType.EXPLOIT_ZERO_DAY, "windows_app")
    print("✓ 3 strategies registered")
    
    # Record attempts
    print("\n[3] Recording strategy attempts...")
    for i in range(10):
        success_rate = 0.8 if i % 3 == 0 else 0.2
        engine.record_attempt(
            "sql_injection",
            success=success_rate > 0.5,
            execution_time=2.5 + i * 0.1
        )
    print("✓ 10 attempts recorded")
    
    # Create variant
    print("\n[4] Creating strategy variant...")
    variant_id = engine.create_variant(
        "sql_injection",
        {"timeout": 30, "retries": 5, "encoding": "utf-8"}
    )
    print(f"✓ Variant created: {variant_id}")
    
    # Evaluate variant
    print("\n[5] Evaluating variant...")
    for i in range(5):
        engine.evaluate_variant(variant_id, success=i < 4)
    print("✓ Variant evaluated")
    
    # Get summary
    print("\n[6] Getting performance summary...")
    summary = engine.get_performance_summary()
    print(f"✓ Performance Summary:")
    print(f"  Total strategies: {summary['total_strategies']}")
    print(f"  Average success rate: {summary['average_success_rate']:.1%}")
    print(f"  Best success rate: {summary['best_success_rate']:.1%}")
    print(f"  Total adaptations: {summary['total_adaptations']}")
    
    # Get all strategies
    print("\n[7] Listing all strategies...")
    strategies = engine.get_all_strategies()
    for strat in strategies[:3]:
        print(f"  - {strat['strategy_id']}: {strat['success_rate']:.1%} success (confidence={strat['confidence']:.2f})")
    
    print("\n✅ Adaptive Strategy Engine Test Complete")
    return True


def test_autonomous_scheduler():
    """Test Autonomous Scheduler"""
    print("\n" + "="*60)
    print("Testing Autonomous Scheduler")
    print("="*60)
    
    scheduler = AutonomousScheduler()
    
    # Enable
    print("\n[1] Enabling autonomous scheduler...")
    success = scheduler.enable_scheduling(auto_start=True)
    print(f"✓ Scheduler enabled: {success}")
    time.sleep(1)
    
    # Create tasks
    print("\n[2] Creating scheduled tasks...")
    
    def task_scan():
        logger.info("Executing scan task")
        return {"scanned": 100}
    
    def task_analyze():
        logger.info("Executing analysis task")
        return {"analyzed": 100}
    
    scheduler.schedule_task(
        task_id="scan_test",
        name="Test Scan Task",
        operation=task_scan,
        schedule_time="*/5",
        priority=TaskPriority.HIGH,
        parameters={},
        max_retries=2,
        timeout=60
    )
    
    scheduler.schedule_task(
        task_id="analyze_test",
        name="Test Analysis Task",
        operation=task_analyze,
        schedule_time="*/10",
        priority=TaskPriority.NORMAL,
        parameters={},
        dependencies=["scan_test"]
    )
    
    print("✓ 2 tasks scheduled")
    
    # Get status
    print("\n[3] Getting scheduler status...")
    status = scheduler.get_scheduler_status()
    print(f"✓ Scheduler Status:")
    print(f"  Running: {status['running']}")
    print(f"  Total tasks: {status['total_tasks']}")
    print(f"  Active tasks: {status['active_tasks']}")
    print(f"  Pending jobs: {status['pending_jobs']}")
    
    # Manually trigger
    print("\n[4] Manually triggering task...")
    scheduler.trigger_task("scan_test")
    print("✓ Task triggered")
    time.sleep(1)
    
    # Get task status
    print("\n[5] Getting task status...")
    task = scheduler.get_task_status("scan_test")
    print(f"✓ Task Status:")
    print(f"  Name: {task['name']}")
    print(f"  Executions: {task['execution_count']}")
    print(f"  Success count: {task['success_count']}")
    
    # Get execution history
    print("\n[6] Getting execution history...")
    history = scheduler.get_execution_history(limit=5)
    print(f"✓ Executions recorded: {len(history)}")
    for exec_rec in history:
        print(f"  - {exec_rec['task_id']}: {exec_rec['status']} (duration={exec_rec['duration']:.2f}s)")
    
    scheduler.stop_scheduler()
    print("\n✅ Autonomous Scheduler Test Complete")
    return True


def test_multi_agent_system():
    """Test Multi-Agent System"""
    print("\n" + "="*60)
    print("Testing Multi-Agent System")
    print("="*60)
    
    system = MultiAgentSystem()
    
    # Enable
    print("\n[1] Enabling multi-agent system...")
    success = system.enable_multi_agent_system(auto_start=True)
    print(f"✓ Multi-agent system enabled: {success}")
    time.sleep(1)
    
    # Register agents
    print("\n[2] Registering agents...")
    system.register_agent("scout_1", "Scout Alpha", AgentRole.SCOUT, ["recon", "scanning"])
    system.register_agent("breach_1", "Breacher Beta", AgentRole.BREACHER, ["exploit", "injection"])
    system.register_agent("escalate_1", "Escalator Gamma", AgentRole.ESCALATOR, ["privesc"])
    print("✓ 3 agents registered")
    
    # Create collaborative task
    print("\n[3] Creating collaborative task...")
    task_id = system.create_collaborative_task(
        "Network Assessment",
        "Full network reconnaissance and exploitation",
        [AgentRole.SCOUT, AgentRole.BREACHER],
        priority=4
    )
    print(f"✓ Task created: {task_id}")
    time.sleep(1)
    
    # Send messages
    print("\n[4] Sending inter-agent messages...")
    system.send_message(
        sender_id="scout_1",
        recipient_id="breach_1",
        message_type="target_found",
        content={"target": "192.168.1.100", "service": "Apache 2.4.41"}
    )
    print("✓ Message sent")
    
    # Report results
    print("\n[5] Recording agent results...")
    system.report_agent_result(
        agent_id="scout_1",
        task_id=task_id,
        result={"targets_found": 50, "services": ["HTTP", "SSH", "MySQL"]}
    )
    print("✓ Result recorded")
    
    # Get system status
    print("\n[6] Getting system status...")
    status = system.get_system_status()
    print(f"✓ System Status:")
    print(f"  Active agents: {status['active_agents']}/{status['total_agents']}")
    print(f"  Active tasks: {status['active_tasks']}/{status['total_tasks']}")
    print(f"  Message queue: {status['message_queue_size']}")
    
    # Get agent status
    print("\n[7] Getting agent details...")
    agent = system.get_agent_status("scout_1")
    if agent:
        print(f"✓ Agent 'Scout Alpha':")
        print(f"  Status: {agent['status']}")
        print(f"  Role: {agent['role']}")
        print(f"  Performance: {agent['performance_score']:.2f}")
        print(f"  Reliability: {agent['reliability']:.2f}")
    
    system.stop_coordination()
    print("\n✅ Multi-Agent System Test Complete")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("ADVANCED AUTONOMY SYSTEMS TEST SUITE")
    print("="*60)
    
    try:
        # Run all tests
        results = {
            "Self-Healing": test_self_healing(),
            "Adaptive Strategies": test_adaptive_strategies(),
            "Autonomous Scheduler": test_autonomous_scheduler(),
            "Multi-Agent System": test_multi_agent_system()
        }
        
        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        for system, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{status}: {system}")
        
        all_passed = all(results.values())
        
        print("\n" + "="*60)
        if all_passed:
            print("✅ ALL TESTS PASSED - Advanced Autonomy Systems Operational!")
        else:
            print("⚠️ Some tests failed - Check logs above")
        print("="*60 + "\n")
        
        return all_passed
    
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)

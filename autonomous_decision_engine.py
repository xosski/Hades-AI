"""
Autonomous Decision Engine for HadesAI Phase 2
Enables intelligent autonomous decision-making with risk assessment
"""

import sqlite3
import json
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class DecisionType(Enum):
    """Types of autonomous decisions"""
    THREAT_RESPONSE = "threat_response"
    RESOURCE_ALLOCATION = "resource_allocation"
    SYSTEM_HARDENING = "system_hardening"
    INCIDENT_ESCALATION = "incident_escalation"
    AUTONOMOUS_EXPLOITATION = "autonomous_exploitation"
    DEFENSE_OPTIMIZATION = "defense_optimization"
    NETWORK_ISOLATION = "network_isolation"


class ConfidenceLevel(Enum):
    """Decision confidence"""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    CRITICAL = 1.0


class RiskLevel(Enum):
    """Risk assessment levels"""
    NONE = 0.0
    LOW = 0.2
    MEDIUM = 0.5
    HIGH = 0.8
    CRITICAL = 1.0


# ==================== DATA CLASSES ====================

@dataclass
class ContextInfo:
    """Contextual information for decision making"""
    threat_level: float
    system_resources: Dict[str, float]  # cpu%, memory%, disk%
    network_status: Dict[str, Any]
    active_threats: List[str]
    system_constraints: Dict[str, Any]
    historical_data: Dict[str, Any]
    user_preferences: Dict[str, Any]


@dataclass
class DecisionOption:
    """Potential decision alternative"""
    option_id: str
    description: str
    actions: List[str]
    expected_outcome: str
    success_probability: float
    resource_requirement: Dict[str, float]
    side_effects: List[str] = field(default_factory=list)
    reversibility: bool = True
    urgency: float = 0.5


@dataclass
class Decision:
    """Made autonomous decision"""
    decision_id: str
    decision_type: DecisionType
    selected_option: str
    confidence: float
    risk_assessment: float
    rationale: str
    actions: List[str]
    constraints_respected: bool
    created_at: float = field(default_factory=time.time)
    executed: bool = False
    result: Optional[Any] = None
    outcome_confidence: float = 0.0
    reversal_possible: bool = True


@dataclass
class DecisionConstraint:
    """Constraints on decision making"""
    constraint_id: str
    name: str
    constraint_type: str  # "hard", "soft", "learning"
    expression: str  # e.g., "cpu_usage < 80" or "budget_remaining > 1000"
    priority: int  # 1-10, higher = stricter
    learn_from_violations: bool = True


@dataclass
class LearningRecord:
    """Learning from decision outcomes"""
    decision_id: str
    expected_outcome: str
    actual_outcome: str
    success: bool
    improvement_potential: float
    feedback_score: float


# ==================== AUTONOMOUS DECISION ENGINE ====================

class AutonomousDecisionEngine:
    """Makes intelligent autonomous decisions with risk assessment"""
    
    def __init__(self, db_path: str = "phase2_autonomous_decisions.db"):
        self.db_path = db_path
        self.decisions: Dict[str, Decision] = {}
        self.constraints: Dict[str, DecisionConstraint] = {}
        self.learning_records: List[LearningRecord] = []
        self.decision_history: List[Decision] = []
        
        # Decision weights
        self.weights = {
            "threat_severity": 0.30,
            "resource_availability": 0.20,
            "success_probability": 0.25,
            "risk_level": -0.15,
            "constraint_compliance": 0.10,
            "learning_feedback": 0.10,
        }
        
        self._init_db()
        self._initialize_default_constraints()
    
    def _init_db(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                decision_id TEXT PRIMARY KEY,
                decision_type TEXT,
                selected_option TEXT,
                confidence REAL,
                risk_assessment REAL,
                rationale TEXT,
                actions TEXT,
                created_at REAL,
                executed INTEGER,
                result TEXT
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS constraints (
                constraint_id TEXT PRIMARY KEY,
                name TEXT,
                constraint_type TEXT,
                expression TEXT,
                priority INTEGER
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS learning_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT,
                expected_outcome TEXT,
                actual_outcome TEXT,
                success INTEGER,
                improvement_potential REAL,
                feedback_score REAL
            )
            """)
            
            conn.commit()
    
    def _initialize_default_constraints(self):
        """Initialize default constraints"""
        default_constraints = [
            DecisionConstraint(
                constraint_id="c_cpu_limit",
                name="CPU Usage Limit",
                constraint_type="hard",
                expression="cpu_usage < 90",
                priority=8
            ),
            DecisionConstraint(
                constraint_id="c_memory_limit",
                name="Memory Usage Limit",
                constraint_type="hard",
                expression="memory_usage < 85",
                priority=8
            ),
            DecisionConstraint(
                constraint_id="c_safety",
                name="Safety Constraint",
                constraint_type="hard",
                expression="not_affecting_critical_systems",
                priority=10
            ),
            DecisionConstraint(
                constraint_id="c_reversibility",
                name="Reversibility Requirement",
                constraint_type="soft",
                expression="decision_reversible",
                priority=6
            ),
            DecisionConstraint(
                constraint_id="c_approval",
                name="Admin Approval",
                constraint_type="soft",
                expression="admin_approval_obtained",
                priority=5
            ),
        ]
        
        for constraint in default_constraints:
            self.constraints[constraint.constraint_id] = constraint
    
    def decide(self, context: ContextInfo, decision_type: DecisionType,
               options: List[DecisionOption]) -> Decision:
        """Make autonomous decision based on context and options"""
        
        decision_id = f"dec_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
        # Evaluate all options
        option_scores = {}
        for option in options:
            score = self._evaluate_option(option, context)
            option_scores[option.option_id] = score
        
        # Select best option
        best_option_id = max(option_scores.keys(), key=lambda x: option_scores[x])
        best_option = next(o for o in options if o.option_id == best_option_id)
        
        # Assess risk and confidence
        risk_assessment = self._assess_risk(best_option, context)
        confidence = self._calculate_confidence(best_option, context, option_scores)
        
        # Check constraint compliance
        constraints_respected = self._check_constraints(best_option, context)
        
        if not constraints_respected and not self._can_override_constraints(context):
            logger.warning(f"Decision {decision_id} violates constraints, falling back to safe option")
            # Select safest option instead
            safe_options = [o for o in options if self._satisfies_all_hard_constraints(o, context)]
            if safe_options:
                best_option = safe_options[0]
                confidence *= 0.7  # Reduce confidence due to fallback
        
        # Generate rationale
        rationale = self._generate_rationale(best_option, context, confidence, risk_assessment)
        
        # Create decision
        decision = Decision(
            decision_id=decision_id,
            decision_type=decision_type,
            selected_option=best_option.option_id,
            confidence=confidence,
            risk_assessment=risk_assessment,
            rationale=rationale,
            actions=best_option.actions,
            constraints_respected=constraints_respected,
            reversal_possible=best_option.reversibility
        )
        
        self.decisions[decision_id] = decision
        self.decision_history.append(decision)
        self._store_decision(decision)
        
        logger.info(f"Decision made: {decision_id} (confidence: {confidence:.2%}, risk: {risk_assessment:.2f})")
        return decision
    
    def _evaluate_option(self, option: DecisionOption, context: ContextInfo) -> float:
        """Score an option"""
        score = 0.0
        
        # Threat severity component
        threat_score = 1.0 - (len(context.active_threats) / 10)  # Normalize
        score += self.weights["threat_severity"] * threat_score
        
        # Resource availability
        resource_score = min(
            (100 - context.system_resources.get("cpu", 0)) / 100,
            (100 - context.system_resources.get("memory", 0)) / 100
        )
        score += self.weights["resource_availability"] * resource_score
        
        # Success probability
        score += self.weights["success_probability"] * option.success_probability
        
        # Risk level (negative contribution)
        risk = 1.0 - option.success_probability  # Approximate risk
        score += self.weights["risk_level"] * risk
        
        # Learning feedback
        learning_score = self._get_option_learning_score(option.option_id)
        score += self.weights["learning_feedback"] * learning_score
        
        return max(0, score)
    
    def _assess_risk(self, option: DecisionOption, context: ContextInfo) -> float:
        """Assess risk of a decision"""
        risk = 0.0
        
        # Base risk from success probability
        risk += (1.0 - option.success_probability) * 0.4
        
        # Resource utilization risk
        for resource, required in option.resource_requirement.items():
            available = context.system_resources.get(resource, 100)
            if available < required:
                risk += 0.2
        
        # Side effects risk
        risk += len(option.side_effects) * 0.1
        
        # Threat level risk
        threat_risk = context.threat_level / 10.0  # Normalize from 10
        risk += threat_risk * 0.2
        
        # Reversibility factor (lower risk if reversible)
        if not option.reversibility:
            risk += 0.15
        
        return min(risk, 1.0)
    
    def _calculate_confidence(self, option: DecisionOption, context: ContextInfo,
                             scores: Dict[str, float]) -> float:
        """Calculate decision confidence"""
        confidence = option.success_probability
        
        # Boost confidence if option is significantly better than others
        average_score = sum(scores.values()) / len(scores)
        option_score = scores[option.option_id]
        
        if option_score > average_score:
            score_margin = (option_score - average_score) / average_score
            confidence += (0.1 * score_margin)  # Boost up to 10%
        
        # Factor in resource availability
        resource_factor = min(
            (100 - context.system_resources.get("cpu", 0)) / 100,
            (100 - context.system_resources.get("memory", 0)) / 100
        )
        confidence *= (0.8 + 0.2 * resource_factor)
        
        return min(confidence, 1.0)
    
    def _check_constraints(self, option: DecisionOption, context: ContextInfo) -> bool:
        """Check if decision respects constraints"""
        for constraint in self.constraints.values():
            if constraint.constraint_type == "hard":
                if not self._evaluate_constraint(constraint, context, option):
                    return False
        return True
    
    def _satisfies_all_hard_constraints(self, option: DecisionOption, context: ContextInfo) -> bool:
        """Check if option satisfies all hard constraints"""
        return self._check_constraints(option, context)
    
    def _evaluate_constraint(self, constraint: DecisionConstraint,
                           context: ContextInfo, option: DecisionOption) -> bool:
        """Evaluate if constraint is satisfied"""
        # Simple constraint evaluation
        if "cpu" in constraint.expression:
            cpu = context.system_resources.get("cpu", 0)
            if "< 90" in constraint.expression:
                return cpu < 90
            elif "< 80" in constraint.expression:
                return cpu < 80
        
        if "memory" in constraint.expression:
            memory = context.system_resources.get("memory", 0)
            if "< 85" in constraint.expression:
                return memory < 85
        
        if "reversible" in constraint.expression:
            return option.reversibility
        
        return True
    
    def _can_override_constraints(self, context: ContextInfo) -> bool:
        """Determine if constraints can be overridden"""
        # Override if threat is critical
        return context.threat_level > 0.8
    
    def _generate_rationale(self, option: DecisionOption, context: ContextInfo,
                           confidence: float, risk: float) -> str:
        """Generate human-readable decision rationale"""
        rationale = f"Selected '{option.description}' "
        rationale += f"(confidence: {confidence:.0%}, risk: {risk:.2f}). "
        
        if context.threat_level > 0.7:
            rationale += "High threat detected. "
        
        if context.system_resources.get("cpu", 0) > 80:
            rationale += "System CPU under stress. "
        
        rationale += f"Expected outcome: {option.expected_outcome}. "
        
        if option.side_effects:
            rationale += f"Potential side effects: {', '.join(option.side_effects[:2])}. "
        
        rationale += f"Reversible: {option.reversibility}"
        
        return rationale
    
    def execute_decision(self, decision_id: str) -> bool:
        """Execute a decision"""
        if decision_id not in self.decisions:
            return False
        
        decision = self.decisions[decision_id]
        
        try:
            logger.info(f"Executing decision {decision_id}: {decision.rationale}")
            # In production, would execute actual actions
            decision.executed = True
            decision.result = "executed_successfully"
            self._store_decision(decision)
            return True
        except Exception as e:
            logger.error(f"Failed to execute decision: {e}")
            decision.result = str(e)
            return False
    
    def record_outcome(self, decision_id: str, actual_outcome: str,
                      success: bool, feedback_score: float = 0.5):
        """Record decision outcome for learning"""
        if decision_id not in self.decisions:
            return
        
        decision = self.decisions[decision_id]
        improvement_potential = 1.0 - decision.confidence if not success else 0.0
        
        record = LearningRecord(
            decision_id=decision_id,
            expected_outcome=decision.rationale,
            actual_outcome=actual_outcome,
            success=success,
            improvement_potential=improvement_potential,
            feedback_score=feedback_score
        )
        
        self.learning_records.append(record)
        self._store_learning_record(record)
        
        # Update weights based on learning
        if len(self.learning_records) % 10 == 0:
            self._update_decision_weights()
        
        logger.info(f"Outcome recorded for {decision_id}: {actual_outcome} (success: {success})")
    
    def _get_option_learning_score(self, option_id: str) -> float:
        """Get learning score for an option"""
        related_records = [
            r for r in self.learning_records
            if option_id in r.decision_id  # Simplified matching
        ]
        
        if not related_records:
            return 0.5  # Neutral score for unknown options
        
        success_rate = sum(1 for r in related_records if r.success) / len(related_records)
        return success_rate
    
    def _update_decision_weights(self):
        """Update decision weights based on learning"""
        # Simplified weight update
        successful_decisions = [
            r for r in self.learning_records[-100:] if r.success
        ]
        
        if successful_decisions:
            avg_confidence = sum(1 for r in successful_decisions) / len(successful_decisions)
            # Adjust weight slightly
            self.weights["success_probability"] *= (1.0 + (avg_confidence - 0.7) * 0.1)
        
        logger.info("Decision weights updated based on learning")
    
    def get_decision_statistics(self) -> Dict[str, Any]:
        """Get decision making statistics"""
        total_decisions = len(self.decision_history)
        executed = sum(1 for d in self.decision_history if d.executed)
        successful = sum(1 for r in self.learning_records if r.success)
        
        return {
            "total_decisions": total_decisions,
            "executed_decisions": executed,
            "successful_outcomes": successful,
            "success_rate": (successful / len(self.learning_records) * 100) if self.learning_records else 0,
            "avg_confidence": (
                sum(d.confidence for d in self.decision_history) / total_decisions
                if total_decisions > 0 else 0
            ),
            "avg_risk": (
                sum(d.risk_assessment for d in self.decision_history) / total_decisions
                if total_decisions > 0 else 0
            ),
            "constraint_violations": sum(1 for d in self.decision_history if not d.constraints_respected),
        }
    
    def _store_decision(self, decision: Decision):
        """Store decision in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO decisions
                (decision_id, decision_type, selected_option, confidence, risk_assessment,
                 rationale, actions, created_at, executed, result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    decision.decision_id,
                    decision.decision_type.value,
                    decision.selected_option,
                    decision.confidence,
                    decision.risk_assessment,
                    decision.rationale,
                    json.dumps(decision.actions),
                    decision.created_at,
                    int(decision.executed),
                    decision.result
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing decision: {e}")
    
    def _store_learning_record(self, record: LearningRecord):
        """Store learning record in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT INTO learning_records
                (decision_id, expected_outcome, actual_outcome, success,
                 improvement_potential, feedback_score)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    record.decision_id,
                    record.expected_outcome,
                    record.actual_outcome,
                    int(record.success),
                    record.improvement_potential,
                    record.feedback_score
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing learning record: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_autonomous_decision():
    """Demonstrate autonomous decision engine"""
    print("=" * 80)
    print("Autonomous Decision Engine Demo")
    print("=" * 80)
    
    engine = AutonomousDecisionEngine()
    
    # Create context
    context = ContextInfo(
        threat_level=0.8,
        system_resources={
            "cpu": 65,
            "memory": 72,
            "disk": 55
        },
        network_status={"status": "normal"},
        active_threats=["CVE-2024-0001", "CVE-2024-0002"],
        system_constraints={},
        historical_data={},
        user_preferences={}
    )
    
    # Create decision options
    options = [
        DecisionOption(
            option_id="opt_1",
            description="Immediate system isolation",
            actions=["isolate_network", "alert_admin", "log_incident"],
            expected_outcome="Threat contained, possible service interruption",
            success_probability=0.95,
            resource_requirement={"cpu": 20, "memory": 15},
            reversibility=False
        ),
        DecisionOption(
            option_id="opt_2",
            description="Enhanced monitoring with gradual response",
            actions=["enable_deep_monitoring", "block_suspicious_ips"],
            expected_outcome="Threat detected and contained with minimal disruption",
            success_probability=0.85,
            resource_requirement={"cpu": 30, "memory": 25},
            reversibility=True,
            side_effects=["slight_performance_degradation"]
        ),
        DecisionOption(
            option_id="opt_3",
            description="Wait and observe",
            actions=["increase_logging", "monitor_carefully"],
            expected_outcome="Understand threat pattern before acting",
            success_probability=0.60,
            resource_requirement={"cpu": 5, "memory": 5},
            reversibility=True
        ),
    ]
    
    # Make decision
    decision = engine.decide(context, DecisionType.THREAT_RESPONSE, options)
    
    print(f"\nDecision ID: {decision.decision_id}")
    print(f"Decision Type: {decision.decision_type.value}")
    print(f"Selected Option: {decision.selected_option}")
    print(f"Confidence: {decision.confidence:.0%}")
    print(f"Risk Assessment: {decision.risk_assessment:.2f}/1.0")
    print(f"Constraints Respected: {decision.constraints_respected}")
    print(f"\nRationale:")
    print(f"  {decision.rationale}")
    print(f"\nActions:")
    for action in decision.actions:
        print(f"  - {action}")
    
    # Execute decision
    print(f"\nExecuting decision...")
    if engine.execute_decision(decision.decision_id):
        print("✓ Decision executed successfully")
    
    # Record outcome
    engine.record_outcome(
        decision.decision_id,
        actual_outcome="Threat successfully contained with minimal impact",
        success=True,
        feedback_score=0.95
    )
    
    # Statistics
    print("\n" + "=" * 80)
    print("Decision Statistics")
    print("=" * 80)
    stats = engine.get_decision_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    demo_autonomous_decision()

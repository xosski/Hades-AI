"""
Memory Feedback Loop - Practical Examples

This module demonstrates the complete feedback loop implementation
for HadesAI's cognitive memory system.
"""

from HadesAI import HadesAI
from typing import Callable, Optional
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LearningHadesAI:
    """
    HadesAI wrapper that implements the complete feedback loop:
    Memory → Generate → Evaluate → Reinforce → Optimize
    """
    
    def __init__(self, hades: HadesAI):
        self.hades = hades
        self.interaction_history = []
        self.start_time = time.time()
    
    def query_with_feedback(
        self,
        user_query: str,
        llm_func: Callable,
        evaluation_func: Optional[Callable] = None
    ) -> dict:
        """
        Complete feedback loop query.
        
        Args:
            user_query: User's question/request
            llm_func: LLM function accepting (prompt) -> response
            evaluation_func: Optional function to evaluate success
                           Signature: (query, response) -> float (0.0-1.0)
        
        Returns:
            Dictionary with response, memories used, success score, etc.
        """
        interaction = {'query': user_query}
        
        # Step 1: Generate with memory context
        logger.info(f"Generating response for: {user_query[:50]}...")
        response, memories = self.hades.generate_with_memory(
            query=user_query,
            llm_call=llm_func
        )
        interaction['response'] = response
        interaction['memories_recalled'] = len(memories)
        
        # Step 2: Evaluate outcome
        if evaluation_func:
            logger.info("Evaluating outcome...")
            success_score = evaluation_func(user_query, response)
        else:
            logger.info("No evaluation provided, assuming success")
            success_score = 1.0
        interaction['success_score'] = success_score
        
        # Step 3: Create reflection
        logger.info(f"Storing reflection with score: {success_score:.2f}")
        reflection_id = self.hades.evaluate_response(
            user_input=user_query,
            ai_output=response,
            success_score=success_score,
            metadata={
                'memories_used': len(memories),
                'response_length': len(response)
            }
        )
        interaction['reflection_id'] = reflection_id
        
        # Step 4: Reinforce memories
        logger.info(f"Reinforcing {len(memories)} memories...")
        for similarity_score, memory in memories:
            self.hades.reinforce_memory(memory.id, success_score)
        
        # Log interaction
        self.interaction_history.append(interaction)
        
        return {
            'response': response,
            'success_score': success_score,
            'memories_used': len(memories),
            'reflection_id': reflection_id
        }
    
    def bulk_learn(
        self,
        queries: list,
        llm_func: Callable,
        evaluation_func: Optional[Callable] = None
    ) -> dict:
        """
        Process multiple queries with feedback loop.
        
        Args:
            queries: List of (user_query, expected_quality) tuples
                    or just user_query strings
            llm_func: LLM function
            evaluation_func: Optional evaluation function
        
        Returns:
            Learning statistics
        """
        logger.info(f"Processing {len(queries)} queries...")
        
        results = []
        for i, query in enumerate(queries, 1):
            if isinstance(query, tuple):
                user_query = query[0]
            else:
                user_query = query
            
            result = self.query_with_feedback(
                user_query=user_query,
                llm_func=llm_func,
                evaluation_func=evaluation_func
            )
            results.append(result)
            
            logger.info(f"  [{i}/{len(queries)}] Score: {result['success_score']:.2f}")
        
        return self._calculate_learning_stats(results)
    
    def _calculate_learning_stats(self, results: list) -> dict:
        """Calculate statistics from batch results."""
        if not results:
            return {}
        
        scores = [r['success_score'] for r in results]
        memories_used = [r['memories_used'] for r in results]
        
        return {
            'total_queries': len(results),
            'avg_success_score': sum(scores) / len(scores),
            'best_success': max(scores),
            'worst_success': min(scores),
            'avg_memories_used': sum(memories_used) / len(memories_used),
            'total_memories_recalled': sum(memories_used)
        }
    
    def show_learning_progress(self) -> None:
        """Display learning progress and statistics."""
        if not self.interaction_history:
            print("No interactions yet")
            return
        
        stats = self.hades.get_full_cognitive_stats()
        
        print("\n" + "="*60)
        print("LEARNING PROGRESS REPORT")
        print("="*60)
        
        # Interaction stats
        print("\nInteractions:")
        print(f"  Total: {len(self.interaction_history)}")
        
        scores = [i['success_score'] for i in self.interaction_history]
        print(f"  Avg success: {sum(scores)/len(scores):.2f}")
        print(f"  Best: {max(scores):.2f}")
        print(f"  Worst: {min(scores):.2f}")
        
        # Memory stats
        mem_stats = stats['memories']
        print("\nMemories:")
        print(f"  Total stored: {mem_stats['total_memories']}")
        print(f"  Avg importance: {mem_stats['avg_importance']:.2f}")
        print(f"  Avg reinforcement: {mem_stats['avg_reinforcement']:.2f}")
        print(f"  Avg access count: {mem_stats.get('avg_access_count', 0):.1f}")
        
        # Learning quality
        quality = stats['integration_quality']
        print("\nLearning Quality:")
        print(f"  Reinforced memories: {quality['reinforced_memories']}")
        print(f"  Frequently used: {quality['frequently_accessed']}")
        
        # Reflection stats
        refl_stats = stats['reflections']
        print("\nReflection Data:")
        print(f"  Total reflections: {refl_stats['total_reflections']}")
        print(f"  Avg success: {refl_stats['avg_success']:.2f}")
        
        print("\n" + "="*60 + "\n")
    
    def show_memory_usage(self) -> None:
        """Show which memories are most valuable."""
        if not self.hades.cognitive or not self.hades.cognitive.store.memories:
            print("No memories stored yet")
            return
        
        print("\n" + "="*60)
        print("TOP MEMORIES BY VALUE")
        print("="*60)
        
        # Sort by reinforcement score * access count
        memories = sorted(
            self.hades.cognitive.store.memories,
            key=lambda m: m.reinforcement_score * (m.access_count + 1),
            reverse=True
        )[:5]
        
        for i, mem in enumerate(memories, 1):
            print(f"\n{i}. {mem.content[:60]}...")
            print(f"   Importance: {mem.importance:.2f}")
            print(f"   Reinforcement: {mem.reinforcement_score:.2f}")
            print(f"   Access count: {mem.access_count}")
            print(f"   Created: {mem.timestamp}")


# ============================================================================
# EXAMPLE EVALUATION FUNCTIONS
# ============================================================================

def keyword_based_evaluation(user_query: str, response: str) -> float:
    """
    Simple heuristic: Score based on keyword presence.
    
    Returns 0.0-1.0 based on how much query content appears in response.
    """
    query_words = set(user_query.lower().split())
    response_words = set(response.lower().split())
    
    # Remove common words
    stopwords = {'the', 'a', 'is', 'to', 'how', 'what', 'why', 'for'}
    query_words -= stopwords
    
    if not query_words:
        return 0.5
    
    overlap = len(query_words & response_words)
    coverage = overlap / len(query_words)
    
    return min(1.0, coverage)


def length_based_evaluation(user_query: str, response: str) -> float:
    """
    Heuristic: Score based on response completeness.
    
    Assumes longer, more detailed responses are better.
    """
    # Minimum 100 chars, maximum 5000 chars for best score
    response_len = len(response)
    
    if response_len < 100:
        return 0.2
    elif response_len > 5000:
        return 0.7  # Penalize overly long responses
    else:
        # Score increases linearly from 100 to 5000 chars
        return 0.4 + 0.6 * (response_len - 100) / (5000 - 100)


def combined_evaluation(user_query: str, response: str) -> float:
    """
    Combine multiple evaluation signals.
    """
    keyword_score = keyword_based_evaluation(user_query, response)
    length_score = length_based_evaluation(user_query, response)
    
    # Weighted average (60% keywords, 40% length)
    combined = 0.6 * keyword_score + 0.4 * length_score
    
    return min(1.0, combined)


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

def example_basic_feedback_loop():
    """Basic example: One query with feedback."""
    print("EXAMPLE 1: Basic Feedback Loop")
    print("-" * 60)
    
    hades = HadesAI()
    learner = LearningHadesAI(hades)
    
    # Store some initial knowledge
    hades.remember(
        "SQL injection bypasses authentication using single quotes",
        importance=0.7,
        metadata={'type': 'security'}
    )
    
    # Simple LLM function (replace with real LLM)
    def simple_llm(prompt):
        return f"Response to: {prompt[:50]}..."
    
    # Query with feedback
    result = learner.query_with_feedback(
        user_query="How does SQL injection work?",
        llm_func=simple_llm,
        evaluation_func=keyword_based_evaluation
    )
    
    print(f"Response: {result['response']}")
    print(f"Success Score: {result['success_score']:.2f}")
    print(f"Memories Used: {result['memories_used']}")


def example_batch_learning():
    """Batch example: Process multiple queries."""
    print("\nEXAMPLE 2: Batch Learning")
    print("-" * 60)
    
    hades = HadesAI()
    learner = LearningHadesAI(hades)
    
    # Store knowledge base
    knowledge = [
        "XSS attacks inject JavaScript into web pages",
        "CSRF tokens prevent unauthorized actions",
        "SQL injection uses malicious SQL statements",
        "Buffer overflow exploits memory management",
        "Path traversal bypasses directory restrictions"
    ]
    
    for item in knowledge:
        hades.remember(item, importance=0.6)
    
    # Batch of queries
    queries = [
        "What is XSS?",
        "How does CSRF protection work?",
        "Explain SQL injection",
        "What is buffer overflow?",
        "How does path traversal work?"
    ]
    
    def mock_llm(prompt):
        return f"Generated response based on: {prompt[:100]}..."
    
    # Process batch with learning
    stats = learner.bulk_learn(
        queries=queries,
        llm_func=mock_llm,
        evaluation_func=combined_evaluation
    )
    
    print(f"Processed {stats['total_queries']} queries")
    print(f"Avg success: {stats['avg_success_score']:.2f}")
    print(f"Avg memories used: {stats['avg_memories_used']:.1f}")
    
    learner.show_learning_progress()


def example_manual_feedback():
    """Manual feedback example: User-guided learning."""
    print("\nEXAMPLE 3: Manual Feedback Loop")
    print("-" * 60)
    
    hades = HadesAI()
    learner = LearningHadesAI(hades)
    
    queries = [
        "What is a security audit?",
        "How to find vulnerabilities?",
        "What are the OWASP Top 10?"
    ]
    
    def mock_llm(prompt):
        return "Detailed response content here"
    
    # Manual evaluation function
    def manual_eval(query, response):
        print(f"\nQuery: {query}")
        print(f"Response: {response[:100]}...")
        rating = input("Rate response (0-10): ")
        try:
            return int(rating) / 10.0
        except ValueError:
            return 0.5
    
    # Process with manual feedback
    for query in queries:
        result = learner.query_with_feedback(
            user_query=query,
            llm_func=mock_llm,
            evaluation_func=manual_eval
        )
        print(f"Recorded with score: {result['success_score']:.2f}")
    
    learner.show_learning_progress()
    learner.show_memory_usage()


if __name__ == "__main__":
    # Run examples
    example_basic_feedback_loop()
    # example_batch_learning()
    # example_manual_feedback()

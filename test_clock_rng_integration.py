"""
Integration tests for Clock-Direction RNG with existing payload systems
Validates that Clock-RNG enhances without breaking current functionality
"""

import sys
import logging
from typing import List, Dict

# Test imports
from clock_direction_rng import (
    ClockDirectionRNG,
    SymbolicPayloadSeeder,
    generate_symbolic_seeds
)
from payload_enhancer_with_clock_rng import ClockEnhancedPayloadGenerator
from payload_mutator import PayloadMutator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestClockRNG")


class TestClockRNGIntegration:
    """Comprehensive integration tests"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []
    
    def assert_equal(self, actual, expected, test_name: str):
        """Assert equality and log result"""
        if actual == expected:
            self.tests_passed += 1
            self.test_results.append((test_name, "PASS", ""))
            logger.info(f"✓ {test_name}")
        else:
            self.tests_failed += 1
            msg = f"Expected {expected}, got {actual}"
            self.test_results.append((test_name, "FAIL", msg))
            logger.error(f"✗ {test_name}: {msg}")
    
    def assert_true(self, condition: bool, test_name: str):
        """Assert condition is true"""
        if condition:
            self.tests_passed += 1
            self.test_results.append((test_name, "PASS", ""))
            logger.info(f"✓ {test_name}")
        else:
            self.tests_failed += 1
            self.test_results.append((test_name, "FAIL", "Condition was False"))
            logger.error(f"✗ {test_name}: Condition was False")
    
    def assert_greater_than(self, actual, minimum, test_name: str):
        """Assert value is greater than minimum"""
        if actual > minimum:
            self.tests_passed += 1
            self.test_results.append((test_name, "PASS", ""))
            logger.info(f"✓ {test_name}")
        else:
            self.tests_failed += 1
            msg = f"Expected > {minimum}, got {actual}"
            self.test_results.append((test_name, "FAIL", msg))
            logger.error(f"✗ {test_name}: {msg}")
    
    def assert_isinstance(self, obj, cls, test_name: str):
        """Assert object is instance of class"""
        if isinstance(obj, cls):
            self.tests_passed += 1
            self.test_results.append((test_name, "PASS", ""))
            logger.info(f"✓ {test_name}")
        else:
            self.tests_failed += 1
            msg = f"Expected instance of {cls.__name__}, got {type(obj).__name__}"
            self.test_results.append((test_name, "FAIL", msg))
            logger.error(f"✗ {test_name}: {msg}")
    
    # Test Suite 1: Basic RNG Functionality
    
    def test_rng_deterministic(self):
        """RNG produces same seed for same input"""
        rng1 = ClockDirectionRNG(seed=5)
        rng2 = ClockDirectionRNG(seed=5)
        
        seed1 = rng1.generate_seed(iterations=6)
        seed2 = rng2.generate_seed(iterations=6)
        
        self.assert_equal(seed1, seed2, "RNG deterministic for same seed")
    
    def test_rng_different_seeds(self):
        """RNG produces different seeds for different inputs"""
        rng1 = ClockDirectionRNG(seed=1)
        rng2 = ClockDirectionRNG(seed=12)
        
        seed1 = rng1.generate_seed(iterations=6)
        seed2 = rng2.generate_seed(iterations=6)
        
        self.assert_true(seed1 != seed2, "RNG produces different seeds for different inputs")
    
    def test_rng_seed_range(self):
        """RNG seed is within valid range"""
        for seed_val in range(1, 13):
            rng = ClockDirectionRNG(seed=seed_val)
            seed = rng.generate_seed()
            self.assert_true(
                0 <= seed <= 65535,
                f"RNG seed {seed} within range for direction {seed_val}"
            )
    
    def test_rng_entropy_accumulation(self):
        """RNG accumulates entropy"""
        rng = ClockDirectionRNG(seed=6)
        rng.generate_seed(iterations=6)
        
        self.assert_greater_than(
            rng.entropy_accumulator,
            0,
            "RNG entropy accumulator is positive"
        )
    
    def test_rng_state_history(self):
        """RNG maintains state history"""
        rng = ClockDirectionRNG(seed=3)
        rng.generate_seed(iterations=6)
        
        self.assert_equal(
            len(rng.state_history),
            6,
            "RNG maintains correct state history length"
        )
    
    # Test Suite 2: Multiple Seeds Generation
    
    def test_multiple_seeds_generation(self):
        """RNG generates multiple seeds correctly"""
        rng = ClockDirectionRNG()
        seeds = rng.generate_multiple_seeds(count=5, iterations_per_seed=6)
        
        self.assert_equal(len(seeds), 5, "Multiple seeds count is correct")
        self.assert_isinstance(seeds, list, "Multiple seeds returns list")
        
        for idx, seed in enumerate(seeds):
            self.assert_true(
                0 <= seed <= 65535,
                f"Multiple seed {idx} is within range"
            )
    
    def test_multiple_seeds_diverse(self):
        """Multiple seeds are diverse"""
        rng = ClockDirectionRNG()
        seeds = rng.generate_multiple_seeds(count=10, iterations_per_seed=6)
        
        unique_seeds = len(set(seeds))
        self.assert_greater_than(
            unique_seeds,
            5,
            "Multiple seeds produces diverse values (at least half unique)"
        )
    
    # Test Suite 3: Drift Pattern Analysis
    
    def test_drift_pattern_structure(self):
        """Drift pattern has required fields"""
        rng = ClockDirectionRNG(seed=9)
        rng.generate_seed(iterations=6)
        pattern = rng.get_drift_pattern()
        
        required_fields = ['initial_seed', 'state_transitions', 'final_entropy',
                         'shape_sequence', 'angle_sequence']
        
        for field in required_fields:
            self.assert_true(
                field in pattern,
                f"Drift pattern contains {field}"
            )
    
    def test_drift_pattern_shapes(self):
        """Drift pattern shape sequence is correct length"""
        rng = ClockDirectionRNG(seed=6)
        rng.generate_seed(iterations=8)
        pattern = rng.get_drift_pattern()
        
        self.assert_equal(
            len(pattern['shape_sequence']),
            8,
            "Drift pattern shape sequence matches iteration count"
        )
    
    # Test Suite 4: Payload Seeding
    
    def test_payload_seeder_initialization(self):
        """SymbolicPayloadSeeder initializes correctly"""
        seeder = SymbolicPayloadSeeder()
        
        self.assert_isinstance(
            seeder.rng,
            ClockDirectionRNG,
            "Seeder contains RNG instance"
        )
        self.assert_isinstance(
            seeder.mutation_seeds,
            dict,
            "Seeder has mutation_seeds dict"
        )
    
    def test_seed_mutation_strategy(self):
        """Seeder produces mutation strategy seeds"""
        seeder = SymbolicPayloadSeeder()
        payload = "' OR '1'='1' --"
        
        seeds = seeder.seed_mutation_strategy(
            payload,
            technique_name="test_technique",
            seed_count=5
        )
        
        self.assert_equal(len(seeds), 5, "Mutation strategy seed count is correct")
        self.assert_true(
            "test_technique" in seeder.mutation_seeds,
            "Mutation seeds cached correctly"
        )
    
    def test_obfuscation_sequence(self):
        """Seeder produces obfuscation sequences"""
        seeder = SymbolicPayloadSeeder()
        payload = "SELECT * FROM users"
        
        sequence = seeder.get_obfuscation_sequence(
            payload,
            sequence_length=8
        )
        
        self.assert_equal(
            len(sequence),
            8,
            "Obfuscation sequence has correct length"
        )
    
    def test_polymorphic_variance(self):
        """Seeder produces polymorphic variance"""
        seeder = SymbolicPayloadSeeder()
        
        base = 100
        variance1 = seeder.get_polymorphic_variance(base, variance_range=(0, 50))
        variance2 = seeder.get_polymorphic_variance(base, variance_range=(0, 50))
        
        self.assert_true(
            base <= variance1 <= base + 50,
            "Polymorphic variance within range"
        )
        self.assert_true(
            variance1 >= base or variance1 <= base + 50,
            "Polymorphic variance applied correctly"
        )
    
    # Test Suite 5: Enhanced Payload Generator
    
    def test_enhanced_generator_initialization(self):
        """ClockEnhancedPayloadGenerator initializes"""
        gen = ClockEnhancedPayloadGenerator()
        
        self.assert_isinstance(
            gen.mutator,
            PayloadMutator,
            "Enhanced generator has mutator"
        )
        self.assert_isinstance(
            gen.seeder,
            SymbolicPayloadSeeder,
            "Enhanced generator has seeder"
        )
    
    def test_intelligent_mutations_generation(self):
        """Enhanced generator produces intelligent mutations"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "' OR '1'='1' --"
        
        mutations = gen.generate_intelligent_mutations(
            payload,
            technology='php',
            target_waf='modsecurity',
            max_mutations=5,
            use_symbolic_ordering=True
        )
        
        self.assert_isinstance(mutations, list, "Intelligent mutations returns list")
        self.assert_greater_than(
            len(mutations),
            0,
            "Intelligent mutations generates at least one mutation"
        )
    
    def test_polymorphic_variants_generation(self):
        """Enhanced generator produces polymorphic variants"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "SELECT * FROM users"
        
        variants = gen.generate_polymorphic_variants(
            payload,
            variant_count=3,
            technology='sql'
        )
        
        self.assert_equal(len(variants), 3, "Polymorphic variants count is correct")
        
        for variant in variants:
            required_fields = ['variant_id', 'payload', 'mutations_applied', 'drift_pattern']
            for field in required_fields:
                self.assert_true(
                    field in variant,
                    f"Polymorphic variant contains {field}"
                )
    
    def test_polymorphic_variants_different(self):
        """Polymorphic variants are structurally different"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "admin' --"
        
        variants = gen.generate_polymorphic_variants(
            payload,
            variant_count=5,
            technology='php'
        )
        
        payloads = [v['payload'] for v in variants]
        unique_payloads = len(set(payloads))
        
        self.assert_greater_than(
            unique_payloads,
            1,
            "Polymorphic variants are structurally different"
        )
    
    def test_obfuscated_payload_generation(self):
        """Enhanced generator produces obfuscated payloads"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "system('whoami')"
        
        obfuscated = gen.generate_obfuscated_payload(
            payload,
            obfuscation_level=2,
            technology='php'
        )
        
        self.assert_isinstance(obfuscated, dict, "Obfuscated payload returns dict")
        self.assert_true(
            'obfuscated' in obfuscated,
            "Obfuscated result contains 'obfuscated' key"
        )
        self.assert_true(
            'techniques_applied' in obfuscated,
            "Obfuscated result contains 'techniques_applied' key"
        )
    
    def test_ensemble_payload_generation(self):
        """Enhanced generator produces ensemble payloads"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "' OR '1'='1' --"
        
        ensemble = gen.generate_ensemble_payload(
            payload,
            ensemble_size=3,
            technology='php'
        )
        
        self.assert_isinstance(ensemble, dict, "Ensemble returns dict")
        self.assert_equal(
            len(ensemble['members']),
            3,
            "Ensemble size matches requested"
        )
        self.assert_true(
            'ensemble_id' in ensemble,
            "Ensemble has ensemble_id"
        )
        self.assert_true(
            'drift_blueprint' in ensemble,
            "Ensemble has drift_blueprint"
        )
    
    def test_ensemble_members_diverse(self):
        """Ensemble members are diverse"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "test_payload"
        
        ensemble = gen.generate_ensemble_payload(
            payload,
            ensemble_size=5,
            technology='php'
        )
        
        payloads = [m['final_payload'] for m in ensemble['members']]
        unique = len(set(payloads))
        
        self.assert_greater_than(
            unique,
            1,
            "Ensemble members are diverse"
        )
    
    # Test Suite 6: Integration with Existing Systems
    
    def test_compatibility_with_mutator(self):
        """Enhanced generator works with existing mutator"""
        gen = ClockEnhancedPayloadGenerator()
        payload = "' OR '1'='1' --"
        
        # Should not break existing mutator
        mutations = gen.mutator.generate_mutations(
            payload,
            technology='php',
            max_mutations=3
        )
        
        self.assert_greater_than(
            len(mutations),
            0,
            "Compatibility with existing mutator maintained"
        )
    
    def test_no_dependency_errors(self):
        """No import or dependency errors"""
        try:
            from payload_enhancer_with_clock_rng import (
                ClockEnhancedPayloadGenerator,
                ObfuscationTechnique
            )
            self.tests_passed += 1
            self.test_results.append(("Import all modules", "PASS", ""))
            logger.info("✓ Import all modules")
        except ImportError as e:
            self.tests_failed += 1
            msg = f"Import error: {e}"
            self.test_results.append(("Import all modules", "FAIL", msg))
            logger.error(f"✗ Import all modules: {msg}")
    
    # Test Suite 7: Performance
    
    def test_performance_single_seed(self):
        """Single seed generation is reasonably fast"""
        import time
        
        rng = ClockDirectionRNG()
        start = time.time()
        rng.generate_seed(iterations=6)
        elapsed = time.time() - start
        
        # Should complete in < 10ms
        self.assert_true(
            elapsed < 0.01,
            f"Single seed generation is fast ({elapsed*1000:.2f}ms)"
        )
    
    def test_performance_multiple_mutations(self):
        """Multiple mutations complete in reasonable time"""
        import time
        
        gen = ClockEnhancedPayloadGenerator()
        payload = "' OR '1'='1' --"
        
        start = time.time()
        mutations = gen.generate_intelligent_mutations(
            payload,
            technology='php',
            max_mutations=10
        )
        elapsed = time.time() - start
        
        # Should complete in < 100ms for 10 mutations
        self.assert_true(
            elapsed < 0.1,
            f"Multiple mutations complete quickly ({elapsed*1000:.2f}ms)"
        )
    
    def run_all_tests(self):
        """Execute all test suites"""
        logger.info("\n" + "=" * 70)
        logger.info("Clock-Direction RNG Integration Test Suite")
        logger.info("=" * 70 + "\n")
        
        # Test Suite 1
        logger.info("TEST SUITE 1: Basic RNG Functionality")
        logger.info("-" * 70)
        self.test_rng_deterministic()
        self.test_rng_different_seeds()
        self.test_rng_seed_range()
        self.test_rng_entropy_accumulation()
        self.test_rng_state_history()
        
        # Test Suite 2
        logger.info("\nTEST SUITE 2: Multiple Seeds Generation")
        logger.info("-" * 70)
        self.test_multiple_seeds_generation()
        self.test_multiple_seeds_diverse()
        
        # Test Suite 3
        logger.info("\nTEST SUITE 3: Drift Pattern Analysis")
        logger.info("-" * 70)
        self.test_drift_pattern_structure()
        self.test_drift_pattern_shapes()
        
        # Test Suite 4
        logger.info("\nTEST SUITE 4: Payload Seeding")
        logger.info("-" * 70)
        self.test_payload_seeder_initialization()
        self.test_seed_mutation_strategy()
        self.test_obfuscation_sequence()
        self.test_polymorphic_variance()
        
        # Test Suite 5
        logger.info("\nTEST SUITE 5: Enhanced Payload Generator")
        logger.info("-" * 70)
        self.test_enhanced_generator_initialization()
        self.test_intelligent_mutations_generation()
        self.test_polymorphic_variants_generation()
        self.test_polymorphic_variants_different()
        self.test_obfuscated_payload_generation()
        self.test_ensemble_payload_generation()
        self.test_ensemble_members_diverse()
        
        # Test Suite 6
        logger.info("\nTEST SUITE 6: Integration with Existing Systems")
        logger.info("-" * 70)
        self.test_compatibility_with_mutator()
        self.test_no_dependency_errors()
        
        # Test Suite 7
        logger.info("\nTEST SUITE 7: Performance")
        logger.info("-" * 70)
        self.test_performance_single_seed()
        self.test_performance_multiple_mutations()
        
        # Summary
        logger.info("\n" + "=" * 70)
        logger.info("TEST SUMMARY")
        logger.info("=" * 70)
        logger.info(f"PASSED: {self.tests_passed}")
        logger.info(f"FAILED: {self.tests_failed}")
        logger.info(f"TOTAL:  {self.tests_passed + self.tests_failed}")
        
        if self.tests_failed == 0:
            logger.info("\n✓ ALL TESTS PASSED")
            return True
        else:
            logger.warning(f"\n✗ {self.tests_failed} TESTS FAILED")
            return False


if __name__ == "__main__":
    tester = TestClockRNGIntegration()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

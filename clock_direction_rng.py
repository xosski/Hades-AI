"""
Clock-Direction RNG: Symbolic Entropy Generator for Payload Mutation
Implements a drift-based random number generator using clock positions, geometric
transformations, and recursive symbolic mapping to create pseudo-random seeds for
payload obfuscation and polymorphic generation.

Core Concept:
- Map 1-12 clock positions to directional impulses
- Each direction selects shape/color combos from a generative set
- Apply recursive transforms (morphing, mixing) to shapes
- Calculate geometric properties (area, volume, perimeter) as entropy
- Chain transformations into polynomial RNG output

This creates "designed chaos" - deterministic but exhibiting high complexity.
Used for:
  * Seed generation for payload mutators
  * Polymorphic payload variants
  * Obfuscation sequence generation
  * WAF fingerprinting through drift patterns
"""

import math
import hashlib
import random
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class Shape(Enum):
    """Geometric shapes for transformation"""
    CIRCLE = "circle"
    TRIANGLE = "triangle"
    SQUARE = "square"
    PENTAGON = "pentagon"
    HEXAGON = "hexagon"
    OCTAGON = "octagon"
    ELLIPSE = "ellipse"
    STAR = "star"


class Color(Enum):
    """Color palette for frequency mapping"""
    RED = (255, 0, 0)
    BLUE = (0, 0, 255)
    GREEN = (0, 255, 0)
    YELLOW = (255, 255, 0)
    CYAN = (0, 255, 255)
    MAGENTA = (255, 0, 255)
    WHITE = (255, 255, 255)
    BLACK = (0, 0, 0)


@dataclass
class GeometricState:
    """Current geometric transformation state"""
    shape: Shape
    color: Color
    angle: float
    scale: float  # Size multiplier
    area: float
    perimeter: float
    symmetry: int  # Number of symmetry axes
    
    def hash_state(self) -> int:
        """Convert state to numeric hash"""
        h = hashlib.md5()
        state_str = f"{self.shape.value}{self.color.name}{self.angle:.2f}{self.scale:.2f}"
        h.update(state_str.encode())
        return int(h.hexdigest(), 16)


class ClockDirectionRNG:
    """
    Symbolic entropy generator using clock-position-based recursive transformations.
    """
    
    # Clock direction mapping (1-12 positions)
    CLOCK_DIRECTIONS = {
        1: {'angle': 30, 'label': 'NE', 'impulse': 0.087},
        2: {'angle': 60, 'label': 'ENE', 'impulse': 0.174},
        3: {'angle': 90, 'label': 'E', 'impulse': 0.261},
        4: {'angle': 120, 'label': 'ESE', 'impulse': 0.348},
        5: {'angle': 150, 'label': 'SE', 'impulse': 0.435},
        6: {'angle': 180, 'label': 'S', 'impulse': 0.522},
        7: {'angle': 210, 'label': 'SW', 'impulse': 0.609},
        8: {'angle': 240, 'label': 'WSW', 'impulse': 0.696},
        9: {'angle': 270, 'label': 'W', 'impulse': 0.783},
        10: {'angle': 300, 'label': 'WNW', 'impulse': 0.870},
        11: {'angle': 330, 'label': 'NW', 'impulse': 0.957},
        12: {'angle': 0, 'label': 'N', 'impulse': 1.0},
    }
    
    # Direction -> Shape/Color mapping
    DIRECTIONAL_ARCHETYPES = {
        1: (Shape.TRIANGLE, Color.RED),      # North - pointed, aggressive
        2: (Shape.STAR, Color.YELLOW),       # NE - explosive
        3: (Shape.PENTAGON, Color.GREEN),    # East - balanced
        4: (Shape.HEXAGON, Color.CYAN),      # ESE - structured
        5: (Shape.SQUARE, Color.BLUE),       # SE - stable
        6: (Shape.OCTAGON, Color.MAGENTA),   # South - complex
        7: (Shape.CIRCLE, Color.BLACK),      # SW - round, absorbing
        8: (Shape.ELLIPSE, Color.WHITE),     # WSW - stretched
        9: (Shape.PENTAGON, Color.RED),      # West - reflection
        10: (Shape.TRIANGLE, Color.GREEN),   # WNW - sharp again
        11: (Shape.SQUARE, Color.BLUE),      # NW - grounded
        12: (Shape.CIRCLE, Color.WHITE),     # N - full circle
    }
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize RNG with optional seed"""
        self.seed = seed if seed is not None else random.randint(1, 12)
        self.state_history: List[GeometricState] = []
        self.entropy_accumulator = 0.0
        
    def _calculate_area(self, shape: Shape, scale: float) -> float:
        """Calculate area for a given shape"""
        base_areas = {
            Shape.CIRCLE: math.pi,
            Shape.TRIANGLE: math.sqrt(3) / 4,
            Shape.SQUARE: 1.0,
            Shape.PENTAGON: (math.sqrt(25 + 10 * math.sqrt(5))) / 4,
            Shape.HEXAGON: (3 * math.sqrt(3)) / 2,
            Shape.OCTAGON: 2 * (1 + math.sqrt(2)),
            Shape.ELLIPSE: math.pi / 2,
            Shape.STAR: 0.5,
        }
        return base_areas.get(shape, 1.0) * (scale ** 2)
    
    def _calculate_perimeter(self, shape: Shape, scale: float) -> float:
        """Calculate perimeter for a given shape"""
        base_perimeters = {
            Shape.CIRCLE: 2 * math.pi,
            Shape.TRIANGLE: 3 * math.sqrt(3),
            Shape.SQUARE: 4.0,
            Shape.PENTAGON: 5.0,
            Shape.HEXAGON: 6.0,
            Shape.OCTAGON: 8.0,
            Shape.ELLIPSE: math.pi * 3,
            Shape.STAR: 10.0,
        }
        return base_perimeters.get(shape, 1.0) * scale
    
    def _morph_shape(self, current_shape: Shape, direction: int) -> Shape:
        """Transform shape based on direction impulse"""
        shapes = list(Shape)
        current_idx = shapes.index(current_shape)
        
        # Drift amount based on direction
        drift = int((self.CLOCK_DIRECTIONS[direction]['impulse'] * len(shapes)))
        new_idx = (current_idx + drift) % len(shapes)
        
        return shapes[new_idx]
    
    def _mix_color(self, color1: Color, color2: Color) -> Color:
        """Mix two colors (returns nearest color in palette)"""
        rgb1 = color1.value
        rgb2 = color2.value
        
        # Simple average mix
        mixed = (
            (rgb1[0] + rgb2[0]) // 2,
            (rgb1[1] + rgb2[1]) // 2,
            (rgb1[2] + rgb2[2]) // 2,
        )
        
        # Find nearest color in palette
        colors = list(Color)
        distances = [
            sum((mixed[i] - c.value[i]) ** 2 for i in range(3))
            for c in colors
        ]
        nearest_idx = distances.index(min(distances))
        
        return colors[nearest_idx]
    
    def _transform_step(
        self,
        current_state: GeometricState,
        direction: int
    ) -> GeometricState:
        """Apply a single transformation step"""
        
        # Get archetype for direction
        archetype_shape, archetype_color = self.DIRECTIONAL_ARCHETYPES[direction]
        clock_info = self.CLOCK_DIRECTIONS[direction]
        
        # Morph shape based on current + direction
        new_shape = self._morph_shape(current_state.shape, direction)
        
        # Mix colors
        new_color = self._mix_color(current_state.color, archetype_color)
        
        # Adjust angle by clock position
        new_angle = (current_state.angle + clock_info['angle']) % 360
        
        # Scale mutation (impulse-based)
        impulse = clock_info['impulse']
        new_scale = current_state.scale * (0.8 + impulse * 0.4)  # 0.8-1.2 range
        
        # Calculate new geometric properties
        new_area = self._calculate_area(new_shape, new_scale)
        new_perimeter = self._calculate_perimeter(new_shape, new_scale)
        
        # Symmetry (# of sides for polygon shapes)
        symmetry_map = {
            Shape.CIRCLE: 1000,  # Infinite symmetry
            Shape.TRIANGLE: 3,
            Shape.SQUARE: 4,
            Shape.PENTAGON: 5,
            Shape.HEXAGON: 6,
            Shape.OCTAGON: 8,
            Shape.ELLIPSE: 2,
            Shape.STAR: 5,
        }
        new_symmetry = symmetry_map.get(new_shape, 1)
        
        return GeometricState(
            shape=new_shape,
            color=new_color,
            angle=new_angle,
            scale=new_scale,
            area=new_area,
            perimeter=new_perimeter,
            symmetry=new_symmetry
        )
    
    def generate_seed(self, iterations: int = 6) -> int:
        """
        Generate a pseudo-random seed through recursive geometric drift
        
        Args:
            iterations: Number of transformation steps (default 6)
        
        Returns:
            Generated random number (0-65535)
        """
        # Initialize state
        initial_shape, initial_color = self.DIRECTIONAL_ARCHETYPES[self.seed]
        state = GeometricState(
            shape=initial_shape,
            color=initial_color,
            angle=self.CLOCK_DIRECTIONS[self.seed]['angle'],
            scale=1.0,
            area=self._calculate_area(initial_shape, 1.0),
            perimeter=self._calculate_perimeter(initial_shape, 1.0),
            symmetry=3
        )
        
        # Drift through transformations
        entropy = 0.0
        direction = self.seed
        
        for i in range(iterations):
            # Apply transformation
            state = self._transform_step(state, direction)
            self.state_history.append(state)
            
            # Accumulate entropy from geometric properties
            entropy += state.area * state.perimeter
            entropy += (state.angle / 360.0)
            entropy += (state.scale / 2.0)
            entropy *= state.symmetry / 10.0
            
            # Drift direction for next iteration
            direction = (direction + i * 3) % 12 or 12
        
        # Convert accumulated entropy to final seed
        self.entropy_accumulator = entropy
        
        # Use hash of final state + entropy for deterministic but complex output
        final_state_hash = state.hash_state()
        entropy_int = int((entropy % 1.0) * 65536)
        
        result = (final_state_hash + entropy_int) % 65536
        
        return result
    
    def generate_multiple_seeds(
        self,
        count: int,
        iterations_per_seed: int = 6
    ) -> List[int]:
        """Generate multiple independent seeds"""
        seeds = []
        for i in range(count):
            # Use previous entropy to seed next iteration
            next_seed = (self.seed + i + int(self.entropy_accumulator)) % 12 or 12
            rng = ClockDirectionRNG(next_seed)
            seeds.append(rng.generate_seed(iterations_per_seed))
        
        return seeds
    
    def get_drift_pattern(self) -> Dict:
        """Get the drift pattern used (for analysis/WAF fingerprinting)"""
        return {
            'initial_seed': self.seed,
            'state_transitions': len(self.state_history),
            'final_entropy': self.entropy_accumulator,
            'shape_sequence': [s.shape.value for s in self.state_history],
            'angle_sequence': [s.angle for s in self.state_history],
        }


class SymbolicPayloadSeeder:
    """
    Use Clock-Direction RNG to seed payload mutation strategies and
    obfuscation techniques.
    """
    
    def __init__(self):
        """Initialize seeder"""
        self.rng = ClockDirectionRNG()
        self.mutation_seeds: Dict[str, List[int]] = {}
    
    def seed_mutation_strategy(
        self,
        payload: str,
        technique_name: str,
        seed_count: int = 5
    ) -> List[int]:
        """
        Generate symbolic seeds for a mutation strategy
        
        Returns list of integers to be used as RNG seeds for mutation selection
        """
        # Create deterministic but symbolic seed based on payload
        payload_hash = int(hashlib.md5(payload.encode()).hexdigest(), 16)
        initial_direction = (payload_hash % 12) or 12
        
        # Generate seed list
        rng = ClockDirectionRNG(initial_direction)
        seeds = rng.generate_multiple_seeds(seed_count)
        
        # Cache
        self.mutation_seeds[technique_name] = seeds
        
        return seeds
    
    def get_obfuscation_sequence(
        self,
        payload: str,
        sequence_length: int = 8
    ) -> List[int]:
        """
        Get a sequence of random integers for obfuscation ordering
        
        Used to determine: encoding order, insertion points, mutation application order
        """
        rng = ClockDirectionRNG(random.randint(1, 12))
        return rng.generate_multiple_seeds(sequence_length)
    
    def get_polymorphic_variance(
        self,
        base_value: int,
        variance_range: Tuple[int, int] = (0, 256)
    ) -> int:
        """
        Apply symbolic variance to a value
        
        Useful for generating slightly different payloads that maintain
        functional equivalence but differ structurally
        """
        rng = ClockDirectionRNG()
        seed = rng.generate_seed()
        
        min_var, max_var = variance_range
        variance = min_var + (seed % (max_var - min_var))
        
        return base_value + variance


# Convenience functions for integration

def create_clock_rng(seed: Optional[int] = None) -> ClockDirectionRNG:
    """Create a Clock-Direction RNG instance"""
    return ClockDirectionRNG(seed)


def generate_symbolic_seed(iterations: int = 6) -> int:
    """Generate single symbolic seed"""
    return ClockDirectionRNG().generate_seed(iterations)


def generate_symbolic_seeds(count: int, iterations: int = 6) -> List[int]:
    """Generate multiple symbolic seeds"""
    return ClockDirectionRNG().generate_multiple_seeds(count, iterations)


if __name__ == "__main__":
    print("=" * 70)
    print("Clock-Direction RNG - Symbolic Entropy Generator")
    print("=" * 70)
    
    # Test 1: Basic seed generation
    print("\nTest 1: Basic Seed Generation")
    rng = ClockDirectionRNG(seed=12)
    seed = rng.generate_seed(iterations=6)
    print(f"  Generated seed: {seed}")
    print(f"  Entropy accumulated: {rng.entropy_accumulator:.4f}")
    
    # Test 2: Multiple seeds
    print("\nTest 2: Multiple Seeds from Single Direction")
    seeds = rng.generate_multiple_seeds(count=5, iterations_per_seed=6)
    print(f"  Generated {len(seeds)} seeds: {seeds}")
    
    # Test 3: Drift pattern
    print("\nTest 3: Drift Pattern Analysis")
    pattern = rng.get_drift_pattern()
    print(f"  Initial direction: {pattern['initial_seed']}")
    print(f"  State transitions: {pattern['state_transitions']}")
    print(f"  Shape sequence: {pattern['shape_sequence'][:3]}...")
    
    # Test 4: Symbolic payload seeder
    print("\nTest 4: Payload-Based Seeding")
    seeder = SymbolicPayloadSeeder()
    payload = "' OR '1'='1' --"
    mutation_seeds = seeder.seed_mutation_strategy(payload, "sql_concat", seed_count=5)
    print(f"  Payload: {payload}")
    print(f"  Mutation seeds: {mutation_seeds}")
    
    # Test 5: Polymorphic variance
    print("\nTest 5: Polymorphic Variance")
    variance1 = seeder.get_polymorphic_variance(100, (0, 50))
    variance2 = seeder.get_polymorphic_variance(100, (0, 50))
    print(f"  Base: 100 -> Variant 1: {variance1}, Variant 2: {variance2}")
    
    print("\n" + "=" * 70)
    print("All tests complete")
    print("=" * 70)

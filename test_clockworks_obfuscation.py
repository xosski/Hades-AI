#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for Clockworks Obfuscation integration
"""

import sys
import json
import logging
import os

# Fix encoding on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from modules.obfuscation_engine import (
    ClockworksObfuscator, keystream, xor_bytes, DriftState, DIRECTIONS
)
from modules.hades_obfuscation_integration import (
    HadesObfuscationIntegration, ObfuscationType, get_obfuscation_service
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_basic_obfuscation():
    """Test basic obfuscation roundtrip"""
    print("\n[TEST] Basic Obfuscation Roundtrip")
    obf = ClockworksObfuscator(seed=7, rounds=9)
    
    original = b"Hello, Clockworks!"
    encrypted = obf.obfuscate_binary(original, format="b64")
    decrypted = obf.deobfuscate(encrypted, format="b64")
    
    assert decrypted == original, "Roundtrip failed"
    print(f"[PASS] Original:   {original}")
    print(f"[PASS] Encrypted:  {encrypted[:50]}...")
    print(f"[PASS] Decrypted:  {decrypted}")
    print("[OK] PASSED")


def test_lua_obfuscation():
    """Test Lua code obfuscation"""
    print("\n[TEST] Lua Obfuscation")
    obf = ClockworksObfuscator(seed=7, rounds=9)
    
    lua_code = "print('Hello from Clockworks!')"
    obfuscated = obf.obfuscate_lua(lua_code)
    
    assert "b64dec" in obfuscated, "Loader not present"
    assert "keystream" in obfuscated, "Keystream not present"
    assert len(obfuscated) > len(lua_code), "Should be larger"
    
    print(f"[OK] Original size:     {len(lua_code)} bytes")
    print(f"[OK] Obfuscated size:   {len(obfuscated)} bytes")
    print(f"[OK] Expansion ratio:   {len(obfuscated) / len(lua_code):.2f}x")
    print("[OK] PASSED")


def test_different_seeds():
    """Test that different seeds produce different outputs"""
    print("\n[TEST] Different Seeds = Different Outputs")
    
    payload = b"test payload"
    
    obf1 = ClockworksObfuscator(seed=7, rounds=9)
    result1 = obf1.obfuscate_binary(payload, format="b64")
    
    obf2 = ClockworksObfuscator(seed=11, rounds=9)
    result2 = obf2.obfuscate_binary(payload, format="b64")
    
    assert result1 != result2, "Different seeds should produce different outputs"
    print(f"[OK] Seed 7:   {result1[:50]}...")
    print(f"[OK] Seed 11:  {result2[:50]}...")
    print("[OK] PASSED - Outputs are different")


def test_different_rounds():
    """Test that different rounds produce different outputs"""
    print("\n[TEST] Different Rounds = Different Outputs")
    
    payload = b"test payload"
    
    obf1 = ClockworksObfuscator(seed=7, rounds=5)
    result1 = obf1.obfuscate_binary(payload, format="b64")
    
    obf2 = ClockworksObfuscator(seed=7, rounds=15)
    result2 = obf2.obfuscate_binary(payload, format="b64")
    
    assert result1 != result2, "Different rounds should produce different outputs"
    print(f"[OK] Rounds 5:  {result1[:50]}...")
    print(f"[OK] Rounds 15: {result2[:50]}...")
    print("[OK] PASSED - Outputs are different")


def test_keystream_determinism():
    """Test that keystream generation is deterministic"""
    print("\n[TEST] Keystream Determinism")
    
    ks1 = keystream(seed=7, n=100, rounds=9)
    ks2 = keystream(seed=7, n=100, rounds=9)
    
    assert ks1 == ks2, "Keystreams should be identical for same seed/rounds"
    print(f"[OK] Keystream 1: {ks1.hex()[:50]}...")
    print(f"[OK] Keystream 2: {ks2.hex()[:50]}...")
    print("[OK] PASSED - Deterministic")


def test_hades_integration():
    """Test Hades AI integration"""
    print("\n[TEST] Hades AI Integration")
    
    service = get_obfuscation_service()
    
    # Test single payload obfuscation
    result = service.obfuscate_payload(
        "test payload",
        ObfuscationType.PAYLOAD,
        seed=7,
        rounds=9
    )
    
    assert "obfuscated" in result, "Missing obfuscated field"
    assert result["type"] == "payload_obfuscated", "Wrong type"
    assert result["seed"] == 7, "Wrong seed"
    assert result["rounds"] == 9, "Wrong rounds"
    
    print(f"[OK] Payload type:        {result['type']}")
    print(f"[OK] Original size:       {result['original_size']} bytes")
    print(f"[OK] Obfuscated size:     {result['obfuscated_size']} bytes")
    print(f"[OK] Seed:                {result['seed']}")
    print(f"[OK] Rounds:              {result['rounds']}")
    print("[OK] PASSED")


def test_polymorphic_generation():
    """Test polymorphic payload generation"""
    print("\n[TEST] Polymorphic Generation")
    
    service = get_obfuscation_service()
    service.clear_cache()
    
    variations = service.generate_polymorph_payload(
        payload="test",
        variations=5,
        payload_type=ObfuscationType.PAYLOAD
    )
    
    assert len(variations) == 5, "Should generate 5 variations"
    
    # Check uniqueness
    obfuscated = [v["obfuscated"] for v in variations]
    assert len(set(obfuscated)) == 5, "All variations should be unique"
    
    print(f"[OK] Generated {len(variations)} variations")
    for i, var in enumerate(variations):
        print(f"  Variation {var['variation']}: seed={var['seed']}, rounds={var['rounds']}")
    
    print("[OK] PASSED - All unique")


def test_batch_obfuscation():
    """Test batch obfuscation"""
    print("\n[TEST] Batch Obfuscation")
    
    service = get_obfuscation_service()
    service.clear_cache()
    
    payloads = ["payload1", "payload2", "payload3"]
    results = service.obfuscate_batch(payloads, ObfuscationType.COMMAND)
    
    assert len(results) == 3, "Should process 3 payloads"
    assert all("obfuscated" in r for r in results), "All should be obfuscated"
    
    print(f"[OK] Processed {len(results)} payloads")
    for i, result in enumerate(results):
        print(f"  Payload {i+1}: {result['obfuscated_size']} bytes")
    
    print("[OK] PASSED")


def test_caching():
    """Test obfuscation caching"""
    print("\n[TEST] Payload Caching")
    
    service = get_obfuscation_service()
    service.clear_cache()
    
    # First call - obfuscate
    result1 = service.obfuscate_payload(
        "test payload",
        cache_key="test_cache_key"
    )
    
    # Second call - should return cached
    result2 = service.obfuscate_payload(
        "test payload",
        cache_key="test_cache_key"
    )
    
    assert result1 == result2, "Cached result should be identical"
    
    stats = service.get_obfuscation_stats()
    assert stats["cached_payloads"] == 1, "Should have 1 cached payload"
    
    print(f"[OK] Cached payloads: {stats['cached_payloads']}")
    print(f"[OK] Cache compression: {stats['compression_ratio']:.2f}x")
    print("[OK] PASSED")


def test_all_payload_types():
    """Test all payload types"""
    print("\n[TEST] All Payload Types")
    
    service = get_obfuscation_service()
    service.clear_cache()
    
    types = [
        ObfuscationType.LUA,
        ObfuscationType.PAYLOAD,
        ObfuscationType.SHELLCODE,
        ObfuscationType.COMMAND,
        ObfuscationType.SCRIPT,
        ObfuscationType.BINARY,
    ]
    
    for ptype in types:
        try:
            result = service.obfuscate_payload(
                "test",
                ptype
            )
            print(f"[OK] {ptype.value:10} - {result['type']}")
        except Exception as e:
            print(f"[FAIL] {ptype.value:10} - FAILED: {e}")
            return False
    
    print("[OK] PASSED - All types supported")
    return True


def test_seed_normalization():
    """Test seed normalization"""
    print("\n[TEST] Seed Normalization")
    
    service = get_obfuscation_service()
    
    # Out of range seed should normalize
    service.set_seed(13)
    assert 1 <= service.default_seed <= 12, "Seed should be normalized"
    
    print(f"[OK] Seed 13 normalized to {service.default_seed}")
    print("[OK] PASSED")


def test_deobfuscation():
    """Test deobfuscation"""
    print("\n[TEST] Deobfuscation")
    
    service = get_obfuscation_service()
    service.clear_cache()
    
    payload = "test deobfuscation"
    
    # Obfuscate
    result = service.obfuscate_payload(
        payload,
        ObfuscationType.PAYLOAD,
        seed=7,
        rounds=9
    )
    
    # Deobfuscate
    original = service.deobfuscate_payload(
        result["obfuscated"],
        ObfuscationType.PAYLOAD,
        seed=7,
        rounds=9
    )
    
    assert original.decode() == payload, "Deobfuscation should recover original"
    print(f"[OK] Original:       {payload}")
    print(f"[OK] Obfuscated:     {result['obfuscated'][:50]}...")
    print(f"[OK] Deobfuscated:   {original.decode()}")
    print("[OK] PASSED")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("CLOCKWORKS OBFUSCATION TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_basic_obfuscation,
        test_lua_obfuscation,
        test_different_seeds,
        test_different_rounds,
        test_keystream_determinism,
        test_hades_integration,
        test_polymorphic_generation,
        test_batch_obfuscation,
        test_caching,
        test_all_payload_types,
        test_seed_normalization,
        test_deobfuscation,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n[FAIL] FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

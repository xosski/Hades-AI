#!/usr/bin/env python3
"""
Threat Type Validation Tool
Validates that threat types are properly enumerated across the system
"""

import sqlite3
import logging
from pathlib import Path
from typing import Dict
from threat_type_enum import ThreatType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatTypeValidator")


class ThreatTypeValidator:
    """Validates threat type usage across the system"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.invalid_threats = []
        self.valid_threats = set()
        self.unknown_threats = set()
    
    def validate_database(self) -> Dict[str, int]:
        """Validate threat types in database"""
        logger.info("Validating threat types in database...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check threat_findings table
            logger.info("Checking threat_findings table...")
            cursor.execute("SELECT DISTINCT threat_type FROM threat_findings")
            findings_count = 0
            
            for row in cursor.fetchall():
                threat_type_str = row[0]
                if threat_type_str:
                    threat_enum = ThreatType.from_string(threat_type_str)
                    
                    if threat_enum == ThreatType.UNKNOWN:
                        self.unknown_threats.add(threat_type_str)
                        logger.warning(f"Unknown threat type in threat_findings: '{threat_type_str}'")
                    else:
                        self.valid_threats.add(threat_enum.value)
                        findings_count += 1
            
            logger.info(f"✓ Checked threat_findings: {findings_count} valid, {len(self.unknown_threats)} unknown")
            
            # Check security_patterns table
            logger.info("Checking security_patterns table...")
            cursor.execute("SELECT DISTINCT pattern_type FROM security_patterns")
            patterns_count = 0
            
            for row in cursor.fetchall():
                pattern_type_str = row[0]
                if pattern_type_str:
                    threat_enum = ThreatType.from_string(pattern_type_str)
                    
                    if threat_enum == ThreatType.UNKNOWN:
                        self.unknown_threats.add(pattern_type_str)
                        logger.warning(f"Unknown threat type in security_patterns: '{pattern_type_str}'")
                    else:
                        self.valid_threats.add(threat_enum.value)
                        patterns_count += 1
            
            logger.info(f"✓ Checked security_patterns: {patterns_count} valid, {len(self.unknown_threats)} unknown")
            
            conn.close()
            
            return {
                'valid_threats': len(self.valid_threats),
                'unknown_threats': len(self.unknown_threats),
                'threat_findings': findings_count,
                'security_patterns': patterns_count
            }
        except Exception as e:
            logger.error(f"Failed to validate database: {e}")
            return {}
    
    def normalize_database(self) -> int:
        """Normalize threat types in database to enum values"""
        logger.info("Normalizing threat types in database...")
        
        updated = 0
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all threat types from threat_findings
            cursor.execute("SELECT id, threat_type FROM threat_findings")
            updates = []
            
            for row_id, threat_type_str in cursor.fetchall():
                if threat_type_str:
                    threat_enum = ThreatType.from_string(threat_type_str)
                    normalized = threat_enum.value
                    
                    if normalized != threat_type_str:
                        updates.append((normalized, row_id))
                        logger.info(f"Normalizing: '{threat_type_str}' → '{normalized}'")
            
            # Apply updates
            for normalized, row_id in updates:
                cursor.execute("UPDATE threat_findings SET threat_type = ? WHERE id = ?", (normalized, row_id))
                updated += 1
            
            # Normalize security_patterns
            cursor.execute("SELECT id, pattern_type FROM security_patterns")
            pattern_updates = []
            
            for row_id, pattern_type_str in cursor.fetchall():
                if pattern_type_str:
                    threat_enum = ThreatType.from_string(pattern_type_str)
                    normalized = threat_enum.value
                    
                    if normalized != pattern_type_str:
                        pattern_updates.append((normalized, row_id))
                        logger.info(f"Normalizing pattern: '{pattern_type_str}' → '{normalized}'")
            
            for normalized, row_id in pattern_updates:
                cursor.execute("UPDATE security_patterns SET pattern_type = ? WHERE id = ?", (normalized, row_id))
                updated += 1
            
            conn.commit()
            conn.close()
            
            logger.info(f"✓ Normalized {updated} threat type entries")
            return updated
        except Exception as e:
            logger.error(f"Failed to normalize database: {e}")
            return 0
    
    def print_valid_threat_types(self):
        """Print all valid threat types"""
        logger.info("\nValid Threat Types:")
        logger.info("=" * 60)
        
        for threat_type in ThreatType:
            if threat_type != ThreatType.UNKNOWN:
                severity = ThreatType.get_severity(threat_type)
                category = ThreatType.get_category(threat_type)
                logger.info(f"  {threat_type.value:<35} [{severity:<8}] ({category})")
        
        logger.info("=" * 60)
    
    def print_unknown_threats(self):
        """Print threats that don't match enum"""
        if self.unknown_threats:
            logger.warning("\nUnknown Threat Types Found:")
            logger.warning("=" * 60)
            for threat in sorted(self.unknown_threats):
                # Find best match
                best_match = ThreatType.from_string(threat)
                if best_match != ThreatType.UNKNOWN:
                    logger.warning(f"  '{threat}' → recommended: '{best_match.value}'")
                else:
                    logger.warning(f"  '{threat}' → NO MATCH (will be set to UNKNOWN)")
            logger.warning("=" * 60)
        else:
            logger.info("✓ No unknown threat types found")


def main():
    """Run validation"""
    import json
    
    validator = ThreatTypeValidator()
    
    logger.info("=" * 60)
    logger.info("THREAT TYPE ENUMERATION VALIDATOR")
    logger.info("=" * 60)
    logger.info("")
    
    # Validate
    stats = validator.validate_database()
    
    if stats:
        logger.info(f"\nValidation Results:")
        logger.info(f"  Valid threat types: {stats['valid_threats']}")
        logger.info(f"  Unknown threat types: {stats['unknown_threats']}")
        logger.info(f"  Threat findings entries: {stats['threat_findings']}")
        logger.info(f"  Security patterns entries: {stats['security_patterns']}")
    
    # Show unknown
    validator.print_unknown_threats()
    
    # Ask to normalize
    if validator.unknown_threats:
        logger.info("\nWould you like to normalize unknown threat types?")
        response = input("Enter 'yes' to normalize, or 'no' to skip: ").strip().lower()
        
        if response == 'yes':
            updated = validator.normalize_database()
            logger.info(f"✓ Normalized {updated} entries")
        else:
            logger.info("Skipped normalization")
    
    # Print all valid types
    logger.info("\nAll Valid Threat Types:")
    validator.print_valid_threat_types()
    
    logger.info("\nValidation Complete!")


if __name__ == "__main__":
    main()

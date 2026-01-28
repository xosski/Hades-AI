"""
Database Schema Migration for Network Share Feature
Adds source_instance column to enable peer tracking
Run once before enabling network sharing
"""

import sqlite3
import sys
from pathlib import Path
from datetime import datetime
import shutil
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DBMigration")


def backup_database(db_path: str = "hades_knowledge.db") -> str:
    """Create backup before migration"""
    backup_dir = Path("db_backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"hades_knowledge_pre_migration_{timestamp}.db"
    
    try:
        shutil.copy2(db_path, backup_file)
        logger.info(f"Database backed up to {backup_file}")
        return str(backup_file)
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise


def add_source_instance_column(db_path: str = "hades_knowledge.db"):
    """Add source_instance column to sync-enabled tables"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check and add source_instance to security_patterns
        try:
            cursor.execute(
                "ALTER TABLE security_patterns ADD COLUMN source_instance TEXT DEFAULT 'local'"
            )
            logger.info("✓ Added source_instance to security_patterns")
        except sqlite3.OperationalError:
            logger.info("◇ source_instance already exists in security_patterns")
        
        # Check and add source_instance to threat_findings
        try:
            cursor.execute(
                "ALTER TABLE threat_findings ADD COLUMN source_instance TEXT DEFAULT 'local'"
            )
            logger.info("✓ Added source_instance to threat_findings")
        except sqlite3.OperationalError:
            logger.info("◇ source_instance already exists in threat_findings")
        
        # Check and add source_instance to experiences
        try:
            cursor.execute(
                "ALTER TABLE experiences ADD COLUMN source_instance TEXT DEFAULT 'local'"
            )
            logger.info("✓ Added source_instance to experiences")
        except sqlite3.OperationalError:
            logger.info("◇ source_instance already exists in experiences")
        
        conn.commit()
        conn.close()
        logger.info("Migration complete!")
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False


def verify_migration(db_path: str = "hades_knowledge.db") -> bool:
    """Verify migration succeeded"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get schema for security_patterns
        cursor.execute("PRAGMA table_info(security_patterns)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if "source_instance" in columns:
            logger.info("✓ Verification passed: source_instance column exists")
            conn.close()
            return True
        else:
            logger.error("✗ Verification failed: source_instance column not found")
            conn.close()
            return False
            
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False


def create_sync_metadata_table(db_path: str = "hades_knowledge.db"):
    """Create sync metadata table for tracking"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_instance_id TEXT NOT NULL,
                sync_timestamp REAL NOT NULL,
                records_merged INTEGER DEFAULT 0,
                backup_path TEXT,
                status TEXT DEFAULT 'success'
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("✓ Created sync_metadata table")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create sync_metadata table: {e}")
        return False


def main():
    """Run complete migration"""
    db_path = "hades_knowledge.db"
    
    # Check database exists
    if not Path(db_path).exists():
        logger.error(f"Database not found: {db_path}")
        return False
    
    logger.info("=" * 60)
    logger.info("HadesAI Database Migration for Network Share Feature")
    logger.info("=" * 60)
    
    # Backup
    try:
        backup_path = backup_database(db_path)
        logger.info(f"Backup location: {backup_path}")
    except Exception as e:
        logger.error(f"Backup failed, aborting migration: {e}")
        return False
    
    # Add columns
    if not add_source_instance_column(db_path):
        logger.error("Column addition failed")
        return False
    
    # Create metadata table
    if not create_sync_metadata_table(db_path):
        logger.error("Metadata table creation failed")
        return False
    
    # Verify
    if not verify_migration(db_path):
        logger.error("Migration verification failed")
        return False
    
    logger.info("=" * 60)
    logger.info("Migration successful!")
    logger.info("You can now enable Network Sharing in the GUI")
    logger.info("=" * 60)
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

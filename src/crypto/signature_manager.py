from .key_generator import KeyGenerator
from .file_signer import FileSigner
from .signature_verifier import SignatureVerifier

class SignatureManager:
    def __init__(self):
        self.key_generator = KeyGenerator()
        self.file_signer = FileSigner()
        self.signature_verifier = SignatureVerifier()

    def generate_key_pair(self, algorithm: str):
        return self.key_generator.generate_key_pair(algorithm)

    def sign_file(self, private_key_pem: str, file_path: str, algorithm: str):
        return self.file_signer.sign_file(private_key_pem, file_path, algorithm)

    def verify_signature(self, public_key_pem: str, file_path: str, signature: bytes, algorithm: str):
        return self.signature_verifier.verify_signature(public_key_pem, file_path, signature, algorithm)

    def _load_public_key(self, public_key_pem: str, algorithm: str):
        return self.signature_verifier._load_public_key(public_key_pem, algorithm)
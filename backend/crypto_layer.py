import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Converts a raw Diffie-Hellman integer S into a uniform 256-bit (32-byte)
    AES key using HKDF-SHA256.
    """
    byte_length = max(1, (shared_secret.bit_length() + 7) // 8)
    secret_bytes = shared_secret.to_bytes(byte_length, byteorder="big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"IIUI-IS-DH-Visualizer-Salt-v1",
        info=b"diffie-hellman-aes-256-gcm-key",
    )
    return hkdf.derive(secret_bytes)


def encrypt_message(aes_key: bytes, plaintext: str) -> dict:
    """Encrypts plaintext using AES-256-GCM with a random 96-bit nonce."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return {
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
    }


def decrypt_message(aes_key: bytes, nonce_hex: str, ciphertext_hex: str) -> str:
    """Decrypts and verifies authenticity tag of AES-256-GCM ciphertext."""
    aesgcm = AESGCM(aes_key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext_bytes.decode("utf-8")


class IdentitySigner:
    """Long-term Ed25519 identity keypair used to authenticate DH public keys."""

    def __init__(self, owner: str):
        self.owner = owner
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()

    def public_hex(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign_dh_public(self, dh_public_value: int) -> str:
        payload = f"{self.owner}:{dh_public_value}".encode("utf-8")
        return self._private_key.sign(payload).hex()

    @staticmethod
    def verify_dh_public(
        signer_pub_hex: str, owner: str, dh_public_value: int, signature_hex: str
    ) -> bool:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(signer_pub_hex)
            )
            payload = f"{owner}:{dh_public_value}".encode("utf-8")
            pub_key.verify(bytes.fromhex(signature_hex), payload)
            return True
        except (InvalidSignature, ValueError):
            return False
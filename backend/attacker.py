import time
from backend.dh_core import DHParty
from backend.crypto_layer import derive_aes_key, decrypt_message, encrypt_message


class MalloryMITM:
    """Simulates an active network attacker sitting between Alice and Bob."""

    def __init__(self, p: int, g: int):
        self.party = DHParty.create("Mallory", p, g)
        self.secret_with_alice: int | None = None
        self.secret_with_bob: int | None = None
        self.aes_key_alice: bytes | None = None
        self.aes_key_bob: bytes | None = None

    def intercept_alice_to_bob(self, alice_pub: int) -> int:
        """Mallory captures Alice's public key A and substitutes her own public key M."""
        self.secret_with_alice = self.party.compute_shared_secret(alice_pub)
        self.aes_key_alice = derive_aes_key(self.secret_with_alice)
        return self.party.public_key

    def intercept_bob_to_alice(self, bob_pub: int) -> int:
        """Mallory captures Bob's public key B and substitutes her own public key M."""
        self.secret_with_bob = self.party.compute_shared_secret(bob_pub)
        self.aes_key_bob = derive_aes_key(self.secret_with_bob)
        return self.party.public_key

    def intercept_and_tamper_message(
        self, nonce_hex: str, ciphertext_hex: str, tamper_text: str | None = None
    ) -> dict:
        """Decrypts Alice's message using S_Alice, reads/alters it, and re-encrypts for Bob."""
        if not self.aes_key_alice or not self.aes_key_bob:
            raise RuntimeError("Mallory has not established MITM keys yet.")

        stolen_plaintext = decrypt_message(self.aes_key_alice, nonce_hex, ciphertext_hex)
        forwarded_plaintext = (
            tamper_text if tamper_text else f"{stolen_plaintext} [Intercepted by Mallory]"
        )
        re_encrypted = encrypt_message(self.aes_key_bob, forwarded_plaintext)

        return {
            "stolen_plaintext": stolen_plaintext,
            "forwarded_plaintext": forwarded_plaintext,
            "re_encrypted": re_encrypted,
        }


def brute_force_discrete_log(p: int, g: int, public_key: int, max_steps: int = 200_000) -> dict:
    """
    Attempts to recover private key 'x' from public_key = g^x mod p.
    Succeeds instantly on educational primes, and demonstrates infeasibility on 2048-bit primes.
    """
    if p.bit_length() > 32:
        return {
            "cracked": False,
            "reason": (
                f"Aborted: Prime is {p.bit_length()} bits (~2^{p.bit_length()} search space). "
                "Brute-forcing this Discrete Logarithm would take longer than the age of the universe."
            ),
            "steps_tried": 0,
            "elapsed_ms": 0.0,
        }

    start = time.perf_counter()
    current = 1
    for x in range(1, min(p, max_steps + 1)):
        current = (current * g) % p
        if current == public_key:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return {
                "cracked": True,
                "recovered_private_key": x,
                "steps_tried": x,
                "elapsed_ms": round(elapsed_ms, 4),
            }

    elapsed_ms = (time.perf_counter() - start) * 1000
    return {
        "cracked": False,
        "reason": f"Exceeded {max_steps} step limit.",
        "steps_tried": max_steps,
        "elapsed_ms": round(elapsed_ms, 4),
    }
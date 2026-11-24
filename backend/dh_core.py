import secrets
from dataclasses import dataclass

# RFC 3526 Group 14 (2048-bit MODP Group) Standard Prime
RFC3526_2048_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

PARAMETER_PRESETS = {
    "educational_tiny": {
        "name": "Educational Tiny (p = 23, g = 5)",
        "p": 23,
        "g": 5,
        "bits": 5,
    },
    "educational_medium": {
        "name": "Educational Medium (p = 104729, g = 12)",
        "p": 104729,
        "g": 12,
        "bits": 17,
    },
    "production_2048": {
        "name": "RFC 3526 Group 14 (2048-bit Safe Prime)",
        "p": int(RFC3526_2048_PRIME_HEX, 16),
        "g": 2,
        "bits": 2048,
    },
}


@dataclass
class DHParty:
    name: str
    p: int
    g: int
    private_key: int
    public_key: int
    shared_secret: int | None = None

    @classmethod
    def create(cls, name: str, p: int, g: int) -> "DHParty":
        # Private key must be strictly between 2 and p - 2
        private_key = secrets.randbelow(p - 3) + 2
        # Core Diffie-Hellman public key formula: A = g^a mod p
        public_key = pow(g, private_key, p)
        return cls(
            name=name,
            p=p,
            g=g,
            private_key=private_key,
            public_key=public_key,
        )

    def compute_shared_secret(self, peer_public_key: int) -> int:
        # Validate peer public key to prevent small-subgroup attacks
        if not (2 <= peer_public_key <= self.p - 2):
            raise ValueError("Invalid peer public key: out of safe range [2, p-2].")
        # Core Diffie-Hellman shared secret formula: S = B^a mod p
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret


def format_int_preview(value: int, max_digits: int = 28) -> str:
    """Formats huge 2048-bit integers cleanly for UI display while preserving full hex."""
    s = str(value)
    if len(s) <= max_digits:
        return s
    return f"{s[:12]}...{s[-12:]} ({value.bit_length()} bits)"
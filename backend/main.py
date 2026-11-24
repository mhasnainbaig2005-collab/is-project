from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.dh_core import PARAMETER_PRESETS, DHParty, format_int_preview
from backend.crypto_layer import (
    IdentitySigner,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)
from backend.attacker import MalloryMITM, brute_force_discrete_log
from backend.extras import register as register_extras

app = FastAPI(title="Diffie-Hellman Key Exchange Visualizer")

# In-memory session state for live classroom demonstration
SESSION = {
    "preset_key": "educational_tiny",
    "mitm_enabled": False,
    "auth_enabled": False,
    "alice": None,
    "bob": None,
    "mallory": None,
    "alice_signer": IdentitySigner("Alice"),
    "bob_signer": IdentitySigner("Bob"),
    "alice_aes_key": None,
    "bob_aes_key": None,
    "handshake_complete": False,
    "handshake_blocked": False,
}


class HandshakeRequest(BaseModel):
    preset_key: str = "educational_tiny"
    mitm_enabled: bool = False
    auth_enabled: bool = False


class MessageRequest(BaseModel):
    plaintext: str
    tamper_text: str | None = None


@app.post("/api/handshake")
def run_handshake(req: HandshakeRequest):
    if req.preset_key not in PARAMETER_PRESETS:
        raise HTTPException(status_code=400, detail="Unknown parameter preset.")

    preset = PARAMETER_PRESETS[req.preset_key]
    p, g = preset["p"], preset["g"]

    alice = DHParty.create("Alice", p, g)
    bob = DHParty.create("Bob", p, g)
    alice_signer = IdentitySigner("Alice")
    bob_signer = IdentitySigner("Bob")

    SESSION.update(
        {
            "preset_key": req.preset_key,
            "mitm_enabled": req.mitm_enabled,
            "auth_enabled": req.auth_enabled,
            "alice": alice,
            "bob": bob,
            "alice_signer": alice_signer,
            "bob_signer": bob_signer,
            "mallory": None,
            "alice_aes_key": None,
            "bob_aes_key": None,
            "handshake_complete": False,
            "handshake_blocked": False,
        }
    )

    events = [
        f"Public parameters agreed: {preset['name']}",
        f"Alice generated private key 'a' and computed A = g^a mod p.",
        f"Bob generated private key 'b' and computed B = g^b mod p.",
    ]

    # Sign public keys with long-term Ed25519 keys
    alice_sig = alice_signer.sign_dh_public(alice.public_key)
    bob_sig = bob_signer.sign_dh_public(bob.public_key)

    transmitted_to_bob = alice.public_key
    transmitted_to_alice = bob.public_key

    mallory_info = None
    if req.mitm_enabled:
        mallory = MalloryMITM(p, g)
        SESSION["mallory"] = mallory
        transmitted_to_bob = mallory.intercept_alice_to_bob(alice.public_key)
        transmitted_to_alice = mallory.intercept_bob_to_alice(bob.public_key)
        events.append(
            "ALERT (Network): Mallory intercepted A and B on the wire and injected her own public key M!"
        )
        mallory_info = {
            "private_key": format_int_preview(mallory.party.private_key),
            "public_key": format_int_preview(mallory.party.public_key),
            "secret_with_alice": format_int_preview(mallory.secret_with_alice),
            "secret_with_bob": format_int_preview(mallory.secret_with_bob),
        }

    # Verify signatures if Authentication Mode is enabled
    if req.auth_enabled:
        alice_valid = IdentitySigner.verify_dh_public(
            alice_signer.public_hex(), "Alice", transmitted_to_bob, alice_sig
        )
        bob_valid = IdentitySigner.verify_dh_public(
            bob_signer.public_hex(), "Bob", transmitted_to_alice, bob_sig
        )
        if not (alice_valid and bob_valid):
            SESSION["handshake_blocked"] = True
            events.append(
                "DEFENSE TRIGGERED: Ed25519 signature verification FAILED! Mallory's forged public key rejected."
            )
            return {
                "status": "blocked",
                "preset": {"key": req.preset_key, "name": preset["name"], "p": format_int_preview(p), "g": g},
                "mitm_enabled": req.mitm_enabled,
                "auth_enabled": req.auth_enabled,
                "alice": {
                    "private_key": format_int_preview(alice.private_key),
                    "public_key": format_int_preview(alice.public_key),
                    "received_key": format_int_preview(transmitted_to_alice),
                    "shared_secret": "BLOCKED",
                    "aes_key_hex": "NONE",
                },
                "bob": {
                    "private_key": format_int_preview(bob.private_key),
                    "public_key": format_int_preview(bob.public_key),
                    "received_key": format_int_preview(transmitted_to_bob),
                    "shared_secret": "BLOCKED",
                    "aes_key_hex": "NONE",
                },
                "mallory": mallory_info,
                "events": events,
            }
        events.append("Ed25519 digital signatures verified: Public keys genuinely belong to Alice & Bob.")

    # Complete Diffie-Hellman shared secret calculation
    alice_secret = alice.compute_shared_secret(transmitted_to_alice)
    bob_secret = bob.compute_shared_secret(transmitted_to_bob)

    alice_aes = derive_aes_key(alice_secret)
    bob_aes = derive_aes_key(bob_secret)

    SESSION["alice_aes_key"] = alice_aes
    SESSION["bob_aes_key"] = bob_aes
    SESSION["handshake_complete"] = True

    if alice_secret == bob_secret:
        events.append("SUCCESS: Alice and Bob derived the EXACT same shared secret & AES-256 key!")
    else:
        events.append(
            "COMPROMISED: Alice and Bob hold DIFFERENT secrets (both paired with Mallory)!"
        )

    return {
        "status": "compromised" if req.mitm_enabled else "secure",
        "preset": {"key": req.preset_key, "name": preset["name"], "p": format_int_preview(p), "g": g},
        "mitm_enabled": req.mitm_enabled,
        "auth_enabled": req.auth_enabled,
        "alice": {
            "private_key": format_int_preview(alice.private_key),
            "public_key": format_int_preview(alice.public_key),
            "received_key": format_int_preview(transmitted_to_alice),
            "shared_secret": format_int_preview(alice_secret),
            "aes_key_hex": alice_aes.hex(),
        },
        "bob": {
            "private_key": format_int_preview(bob.private_key),
            "public_key": format_int_preview(bob.public_key),
            "received_key": format_int_preview(transmitted_to_bob),
            "shared_secret": format_int_preview(bob_secret),
            "aes_key_hex": bob_aes.hex(),
        },
        "mallory": mallory_info,
        "events": events,
    }


@app.post("/api/send-message")
def send_encrypted_message(req: MessageRequest):
    if SESSION["handshake_blocked"]:
        raise HTTPException(
            status_code=400,
            detail="Handshake was blocked due to MITM signature failure. Reset handshake first.",
        )
    if not SESSION["handshake_complete"]:
        raise HTTPException(status_code=400, detail="Run Key Exchange Handshake first.")

    # 1. Alice encrypts with her derived AES-256-GCM key
    wire_packet = encrypt_message(SESSION["alice_aes_key"], req.plaintext)
    mallory_log = None

    # 2. If Mallory is active, she decrypts, reads/modifies, and re-encrypts for Bob
    if SESSION["mitm_enabled"] and SESSION["mallory"]:
        tamper_result = SESSION["mallory"].intercept_and_tamper_message(
            wire_packet["nonce_hex"],
            wire_packet["ciphertext_hex"],
            req.tamper_text,
        )
        mallory_log = {
            "stolen_plaintext": tamper_result["stolen_plaintext"],
            "forwarded_plaintext": tamper_result["forwarded_plaintext"],
        }
        wire_packet = tamper_result["re_encrypted"]

    # 3. Bob decrypts with his derived AES-256-GCM key
    bob_decrypted = decrypt_message(
        SESSION["bob_aes_key"],
        wire_packet["nonce_hex"],
        wire_packet["ciphertext_hex"],
    )

    return {
        "alice_sent": req.plaintext,
        "wire_nonce": wire_packet["nonce_hex"],
        "wire_ciphertext": wire_packet["ciphertext_hex"],
        "mallory_log": mallory_log,
        "bob_received": bob_decrypted,
    }


@app.post("/api/crack-demo")
def crack_alice_key():
    alice: DHParty | None = SESSION.get("alice")
    if not alice:
        raise HTTPException(status_code=400, detail="Run Key Exchange Handshake first.")

    result = brute_force_discrete_log(alice.p, alice.g, alice.public_key)
    result["actual_private_key"] = format_int_preview(alice.private_key)
    return result


register_extras(app, SESSION)  # must come before the static mount

# Serve the frontend folder at root "/"
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
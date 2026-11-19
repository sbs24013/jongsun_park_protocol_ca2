import tempfile
import os

from src.protocol import SmartMeterProtocol
from src.flawed import FlawedSmartMeterProtocol


# XOR operation
def xor_bytes(a, b, c):
    if not (len(a) == len(b) == len(c)):
        raise ValueError("Message lengths must match")

    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


# Recover plaintext using a known plaintext
def recover_plaintext(packet1, packet2, known_plaintext):

    # Remove the 16-byte authentication tag
    ciphertext1 = packet1["ciphertext"][:-16]
    ciphertext2 = packet2["ciphertext"][:-16]

    return xor_bytes(ciphertext1, ciphertext2, known_plaintext)


# Run Nonce Reuse attack
def run_attack():

    # Generate AES-256 key
    key = os.urandom(32)

    # Smart Meter messages
    message1 = b"Meter=1001;Usage=250kWh"
    message2 = b"Meter=1001;Usage=350kWh"

    # Test vulnerable implementation
    flawed = FlawedSmartMeterProtocol(key, "METER-1001")

    p1 = flawed.encrypt(message1)
    p2 = flawed.encrypt(message2)

    recovered = recover_plaintext(p1, p2, message1)

    attack_success = p1["nonce"] == p2["nonce"] and recovered == message2

    print("Nonce Reuse Attack")
    print("Flawed Version:", "SUCCESS" if attack_success else "FAILED")

    # Test correct implementation
    with tempfile.TemporaryDirectory() as tmp:

        secure = SmartMeterProtocol(key, "METER-1001", f"{tmp}/meter.db")

        s1 = secure.encrypt(message1)
        s2 = secure.encrypt(message2)

        recovered_secure = recover_plaintext(s1, s2, message1)

        secure_blocked = s1["nonce"] != s2["nonce"] and recovered_secure != message2

        print("Correct Version:", "BLOCKED" if secure_blocked else "VULNERABLE")

    # Check final result
    if attack_success and secure_blocked:
        print("Overall Result: PASS")
        return 0

    print("Overall Result: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(run_attack())

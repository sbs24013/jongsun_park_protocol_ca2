from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.flawed import FlawedSmartMeterProtocol
from src.protocol import SmartMeterProtocol
from attack.attack import recover_plaintext


# Test attack success on flawed implementation
def test_attack_succeeds_on_flawed():

    key = AESGCM.generate_key(bit_length=256)

    meter = FlawedSmartMeterProtocol(key, "METER-1001")

    message1 = b"Meter=1001;Usage=250kWh"
    message2 = b"Meter=1001;Usage=350kWh"

    # Encrypt two messages using the same nonce
    p1 = meter.encrypt(message1)
    p2 = meter.encrypt(message2)

    # Recover the second plaintext
    recovered = recover_plaintext(p1, p2, message1)

    assert p1["nonce"] == p2["nonce"]
    assert recovered == message2


# Test attack failure on correct implementation
def test_attack_fails_on_correct(tmp_path):

    key = AESGCM.generate_key(bit_length=256)

    meter = SmartMeterProtocol(key, "METER-1001", str(tmp_path / "state.db"))

    message1 = b"Meter=1001;Usage=250kWh"
    message2 = b"Meter=1001;Usage=350kWh"

    # Encrypt two messages using different nonces
    p1 = meter.encrypt(message1)
    p2 = meter.encrypt(message2)

    # Verify nonce uniqueness
    assert p1["nonce"] != p2["nonce"]

    # Attempt plaintext recovery
    recovered = recover_plaintext(p1, p2, message1)

    assert recovered != message2

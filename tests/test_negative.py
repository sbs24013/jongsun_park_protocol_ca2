import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.protocol import SmartMeterProtocol


# Test rejection of modified ciphertext
def test_modified_ciphertext(tmp_path):

    key = AESGCM.generate_key(bit_length=256)

    meter = SmartMeterProtocol(key, "METER-1001", str(tmp_path / "state.db"))

    packet = meter.encrypt(b"Usage: 250 kWh")

    # Modify ciphertext
    packet["ciphertext"] = (
        bytes([packet["ciphertext"][0] ^ 1]) + packet["ciphertext"][1:]
    )

    # Authentication must fail
    with pytest.raises(InvalidTag):
        meter.decrypt(packet)


# Test Replay Attack protection
def test_replay_protection(tmp_path):

    key = AESGCM.generate_key(bit_length=256)

    meter = SmartMeterProtocol(key, "METER-1001", str(tmp_path / "state.db"))

    packet = meter.encrypt(b"Usage: 250 kWh")

    # Accept the original message
    assert meter.decrypt(packet) == b"Usage: 250 kWh"

    # Reject the repeated message
    with pytest.raises(ValueError, match="Replay"):
        meter.decrypt(packet)

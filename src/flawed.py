from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
import os


# AES-GCM smart meter implementation
class FlawedSmartMeterProtocol:

    def __init__(self, key, meter_id):

        self.key = key
        self.meter_id = meter_id
        self.aes = AESGCM(key)

        self.counter = 0

    # Encrypt each message with a fresh nonce
    def encrypt(self, plaintext):

        self.counter += 1
        counter = self.counter
        nonce = os.urandom(12)

        aad = f"{self.meter_id}:{counter}".encode()

        ciphertext = self.aes.encrypt(nonce, plaintext, aad)

        return {
            "meter_id": self.meter_id,
            "counter": counter,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }


# Run implementation
if __name__ == "__main__":

    key = AESGCM.generate_key(bit_length=256)

    meter = FlawedSmartMeterProtocol(key, "METER-1001")

    packet1 = meter.encrypt(b"Electricity Usage: 250 kWh")
    packet2 = meter.encrypt(b"Electricity Usage: 350 kWh")

    print("AES-GCM")
    print("Nonce Reuse: NOT DETECTED")
    print("Same Nonce:", packet1["nonce"] == packet2["nonce"])
    print("Same Key: YES")

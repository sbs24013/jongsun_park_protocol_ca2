from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Vulnerable AES-GCM implementation
class FlawedSmartMeterProtocol:

    def __init__(self, key, meter_id):

        self.key = key
        self.meter_id = meter_id
        self.aes = AESGCM(key)

        # Reuse the same nonce (vulnerability)
        self.nonce = b"\x00" * 12

    # Encrypt message with a reused nonce
    def encrypt(self, plaintext):

        # Counter is not updated
        counter = 1

        aad = f"{self.meter_id}:{counter}".encode()

        ciphertext = self.aes.encrypt(self.nonce, plaintext, aad)

        return {
            "meter_id": self.meter_id,
            "counter": counter,
            "nonce": self.nonce,
            "ciphertext": ciphertext,
        }


# Run vulnerable implementation
if __name__ == "__main__":

    key = AESGCM.generate_key(bit_length=256)

    meter = FlawedSmartMeterProtocol(key, "METER-1001")

    packet1 = meter.encrypt(b"Electricity Usage: 250 kWh")
    packet2 = meter.encrypt(b"Electricity Usage: 350 kWh")

    print("Flawed AES-GCM")
    print("Nonce Reuse: DETECTED")
    print("Same Nonce:", packet1["nonce"] == packet2["nonce"])
    print("Same Key: YES")

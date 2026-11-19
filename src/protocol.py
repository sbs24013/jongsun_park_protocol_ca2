import os
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore


# Manage persistent Nonce counters
class NonceManager:

    def __init__(self, db_path):
        self.db_path = db_path
        self.initialize()

    # Initialize counter storage
    def initialize(self):

        with sqlite3.connect(self.db_path) as db:

            db.execute("""
                CREATE TABLE IF NOT EXISTS nonce_state (
                    id INTEGER PRIMARY KEY,
                    prefix BLOB NOT NULL,
                    counter INTEGER NOT NULL
                )
            """)

            db.execute(
                """
                INSERT OR IGNORE INTO nonce_state
                VALUES (1, ?, 0)
            """,
                (os.urandom(4),),
            )

            db.execute("""
                CREATE TABLE IF NOT EXISTS replay_state (
                    id INTEGER PRIMARY KEY,
                    last_counter INTEGER NOT NULL
                )
            """)

            db.execute("""
                INSERT OR IGNORE INTO replay_state
                VALUES (1, 0)
            """)

    # Generate a unique 96-bit Nonce
    def next_nonce(self):

        with sqlite3.connect(self.db_path) as db:

            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")

            prefix, counter = db.execute(
                "SELECT prefix, counter FROM nonce_state WHERE id=1"
            ).fetchone()

            counter += 1

            if counter >= 2**64:
                raise OverflowError("Nonce counter exhausted")

            db.execute("UPDATE nonce_state SET counter=? WHERE id=1", (counter,))

            db.commit()

        nonce = prefix + counter.to_bytes(8, "big")

        return nonce, counter

    # Check and update received message counter
    def verify_counter(self, counter):

        with sqlite3.connect(self.db_path) as db:

            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")

            last_counter = db.execute(
                "SELECT last_counter FROM replay_state WHERE id=1"
            ).fetchone()[0]

            if counter <= last_counter:
                raise ValueError("Replay attack detected")

            db.execute("UPDATE replay_state SET last_counter=? WHERE id=1", (counter,))

            db.commit()


# Secure Smart Meter protocol
class SmartMeterProtocol:

    def __init__(self, key, meter_id, db_path):

        self.key = key
        self.meter_id = meter_id
        self.aes = AESGCM(key)

        self.nonce_manager = NonceManager(db_path)

    # Encrypt Smart Meter message
    def encrypt(self, plaintext):

        nonce, counter = self.nonce_manager.next_nonce()

        aad = f"{self.meter_id}:{counter}".encode()

        ciphertext = self.aes.encrypt(nonce, plaintext, aad)

        return {
            "meter_id": self.meter_id,
            "counter": counter,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    # Decrypt and verify message
    def decrypt(self, packet):

        if packet["meter_id"] != self.meter_id:
            raise ValueError("Invalid meter ID")

        counter = packet["counter"]

        aad = f"{self.meter_id}:{counter}".encode()

        # Verify authentication tag
        plaintext = self.aes.decrypt(packet["nonce"], packet["ciphertext"], aad)

        # Prevent replay attacks
        self.nonce_manager.verify_counter(counter)

        return plaintext


# Run normal implementation
if __name__ == "__main__":

    key = AESGCM.generate_key(bit_length=256)

    meter = SmartMeterProtocol(key, "METER-1001", "meter_state.db")

    message = b"Electricity Usage: 250 kWh"

    packet = meter.encrypt(message)
    recovered = meter.decrypt(packet)

    print("Normal AES-GCM")
    print("Encryption: SUCCESS")
    print("Decryption:", recovered.decode())
    print("Nonce:", packet["nonce"].hex())
    print("Counter:", packet["counter"])

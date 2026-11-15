from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Verify AES-GCM using a NIST test vector
def test_aes_gcm_nist_vector():

    # AES-256 test vector
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b""
    aad = b""

    aes = AESGCM(key)

    result = aes.encrypt(nonce, plaintext, aad)

    # Expected NIST authentication tag
    expected = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

    assert result == expected


# Test AES-GCM encryption and decryption
def test_aes_gcm_decryption():

    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)

    nonce = bytes(12)
    plaintext = b"Smart Meter Test"
    aad = b"METER-1001"

    # Encrypt message
    encrypted = aes.encrypt(nonce, plaintext, aad)

    # Decrypt message
    decrypted = aes.decrypt(nonce, encrypted, aad)

    assert decrypted == plaintext

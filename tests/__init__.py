# Security tests for normal and flawed implementations.
#
# 1. test_vectors.py
# Verify AES-GCM encryption and decryption.
# - NIST test vectors
# - Encryption and decryption
# - Nonce and authentication tag
#
# 2. test_negative.py
# Verify rejection of invalid messages.
# - Invalid key and nonce
# - Modified ciphertext
# - Invalid authentication tag
# - Duplicate counter
# - Replay messages
#
# 3. test_attack.py
# Compare attack results between implementations.
# - Attack on flawed.py: SUCCESS
# - Attack on protocol.py: BLOCKED
# - Modified ciphertext: REJECTED
# - Replay message: REJECTED
#
# Expected result:
# The attack must recover plaintext from the
# flawed implementation but fail on the correct
# implementation.

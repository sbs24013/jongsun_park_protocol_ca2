# Smart Meter AES-GCM Security Project (CA2)

## 1. Project Overview

This project implements an AES-GCM communication protocol
for an Irish Energy Utility Smart Meter Network.

It compares a secure implementation with an
intentionally vulnerable implementation to evaluate
the impact of AES-GCM Nonce Reuse.

## 2. Protocol Configuration

- Protocol: AEAD (AES-GCM)
- Algorithm: AES-256-GCM
- Key Size: 256-bit
- Nonce Size: 96-bit
- AAD: Smart Meter ID and Counter
- Replay Protection: Counter-based validation

## 3. Security Vulnerability

The flawed implementation intentionally reuses
the same Nonce under the same AES-GCM key.

This vulnerability can compromise:

- Confidentiality
- Message Integrity
- Authentication Security

## 4. Installation

Install the required Python libraries.

```bash
pip install -r requirements.txt
```

## 5. Run Protocols

Run the normal and vulnerable implementations.

```bash
make run
```

## 6. Execute Attack

Perform the AES-GCM Nonce Reuse attack.

```bash
make attack
```

## 7. Run Security Tests

Run all automated security tests.

```bash
make test
```

## 8. Clean Temporary Files

Remove temporary files and caches.

```bash
make clean
```

## 9. Expected Results

| Test                      | Expected Result |
| ------------------------- | --------------- |
| Normal AES-GCM            | PASS            |
| Flawed AES-GCM            | VULNERABLE      |
| Nonce Reuse Attack        | SUCCESS         |
| Attack on Correct Version | BLOCKED         |
| Security Tests            | PASSED          |

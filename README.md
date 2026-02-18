# Lab03DHProgram

A Python lab that demonstrates:
1) **Diffie–Hellman key exchange** to establish a shared secret,  
2) using that shared secret to seed a **stateful SHA-256–based PRNG**, and  
3) encrypting messages by XOR-ing the plaintext with a PRNG-generated keystream.

The program also includes a **Mallory man-in-the-middle (MITM)** simulation to show how an attacker can intercept a DH exchange (when it is not authenticated), decrypt messages, modify them, and re-encrypt them so the receiver does not immediately notice. :contentReference[oaicite:1]{index=1}

---

## Files
- `Lab03DHProgram.py` — main script (contains SecurePRNG, entities Alice/Bob, Network, and Mallory MITM logic). :contentReference[oaicite:2]{index=2}

---

## Requirements
- Python 3.x  
- No external libraries required (uses Python standard library: `hashlib`, `secrets`, `os`). :contentReference[oaicite:3]{index=3}

---

## How to Run

### Option 1: Run directly with Python
```bash
python3 Lab03DHProgram.py

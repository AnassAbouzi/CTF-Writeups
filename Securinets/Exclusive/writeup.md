# Exclusive Contents (Crypto) — Securinets CTF Quals 2025

## Overview

The server encrypts data using **AES-XTS** with a **single random key** and a **single random tweak** reused for the whole session, then offers a decryption oracle that **prints the first plaintext block** of any ciphertext we submit. This is enough to recover the flag.

---

## What the server gives us

Let the chosen flag block be `F` (16 bytes for blocks 1–4). The server returns a “clue” ciphertext for:

- plaintext: `R || F`, where `R` is 16 random bytes
- ciphertext: `C1 || C2` (two 16-byte blocks)

Then we can submit any ciphertext `X`, and the server prints:

- `P0 = dec(X)[0:16]` (the first decrypted block)

---

## The core bug: ciphertext stealing + a plaintext leak

AES-XTS supports data lengths that are **not a multiple of 16** using **ciphertext stealing**. The last “partial block” causes the mode to shuffle bytes between the final two blocks.

That matters because we can:

1. Request `C1 || C2 = enc(R || F)`
2. Submit carefully **truncated / re-ordered** ciphertexts so that, due to ciphertext stealing, the server’s printed first block becomes a function of:
   - bytes we control/guess, and
   - exactly one unknown byte of the flag

Once we can build two different ciphertext queries whose leaked `P0` values are **equal if and only if** our guessed byte is correct, we get a byte-by-byte recovery method.

---

## Recovering blocks 1–4 (all but 1 byte each)

For a full 16-byte flag block `F`, we do:

### Step A — Get a reference output `S`

1. Ask the server to generate a clue for a target block ⇒ receive `C1 || C2`.
2. Submit a *crafted* ciphertext that uses `C2` plus a truncated prefix of `C1`, so the total length triggers ciphertext stealing.
3. Record the returned `exclusive_content` as a reference value `S`.

In the provided solver, this looks like:

- split `r` (hex clue) into:
  - `enc_pre = C1`
  - `enc_flg = C2`
- submit: `payload = C2 || C1[:-k]`
- store oracle output as `S`

### Step B — Brute-force the next unknown byte

Assume we’ve already recovered a suffix of the block (or we’re growing it), and we want to find the next byte. We:

1. Build a ciphertext of the form `C1[:-k] || guess || known_suffix`
2. Submit it to the oracle
3. If the oracle output equals `S`, the guess byte is correct

Repeat until we recover as many bytes as possible.

### Why one byte per block remains missing

This technique relies on having at least **one byte “in the last partial block”** to activate ciphertext stealing in the right way. That prevents us from recovering the **first byte** of each of these 16-byte blocks with the same approach.

So after doing this on blocks 1–4, we have 4 blocks where **15/16 bytes are known**, and we still need the **first byte** of blocks 2–5 (see the final brute force section below).

---

## Recovering the last block (shorter than 16 bytes)

The last flag chunk is not necessarily a full 16 bytes, which makes the XTS ciphertext-stealing behavior slightly different.

The solver’s approach is:

1. Request the clue for the last block, get ciphertext pieces.
2. Use the oracle to recover the missing bytes of `enc(R)` (the internal “encrypted random prefix”) **byte-by-byte**:
   - append one byte to the ciphertext,
   - check when the decrypted first block equals the previously recovered `R`
3. Once `enc(R)` is known, do the same comparison trick as before to recover the remaining bytes of the last flag chunk (again, all but the first byte).

This is exactly what the “step 2” section in the solver implements.

---

## Finishing: brute force the 4 missing bytes with SHA-256

At the end we’re missing **4 characters** (the first byte of blocks 2, 3, 4, and 5). The challenge provides a target SHA-256 hash of the full flag, so we brute force these 4 bytes over a small alphabet and check which candidate matches the hash.

---

## Lessons learned

- **XTS is for storage encryption**, where the tweak changes per sector/data-unit. A **fixed tweak** reused across unrelated messages is a design mistake.
- A decryption oracle that returns **raw plaintext** (even just one block) is almost always fatal.
- Use an **AEAD mode** (e.g., AES-GCM or ChaCha20-Poly1305) and **reject invalid ciphertexts without revealing plaintext**.

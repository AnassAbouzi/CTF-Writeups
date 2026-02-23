# "Clandescriptorius (Crypto) — Buckeye CTF 2025"

> description: Chosen-plaintext recovery via keystream collisions from ambiguous (timestamp || block_index) concatenation.

## Overview

The service encrypts data in 16-byte blocks by XORing each plaintext block with a keystream derived from SHA-256. This is stream-cipher style encryption:

$$
C_i = P_i \oplus KS(\text{timestamp}, i)
$$

Two things make it breakable:

1. **Linearity of XOR** (typical stream-cipher property): if you can reproduce the same keystream, XOR cancels and plaintext falls out.  
2. The keystream input is built using **string concatenation of `timestamp` and `block_index` with no delimiter**, which allows **collisions** (different pairs serialize to the same string), producing the *same* keystream.

The `/encrypt` endpoint is a chosen-plaintext oracle, and timestamps are attacker-controlled (only required to be strictly increasing), so we can exploit these collisions to recover the flag block-by-block.

---

## The encryption model

For block index `i`:

- Compute a 16-byte keystream block:
  $
  KS(\text{timestamp}, i) = \text{SHA256}(\text{...} || \text{str(timestamp)} || \text{str(i)})[0:16]
  $
- Encrypt:
  $
  C_i = P_i \oplus KS(\text{timestamp}, i)
  $

The plaintext is PKCS#7 padded to a multiple of 16 bytes. If the message length is *already* a multiple of 16, PKCS#7 adds a full extra block of padding.

---

## Core bug: `(timestamp, index)` serialization collisions

Because the keystream input contains: 

str(timestamp) + str(block_index)


(with no separator), different pairs can produce the same concatenated string.

Example collision:

- `timestamp = -1111`, `index = 0`  → `"-11110"`
- `timestamp = -111`,  `index = 10` → `"-11110"`

So:

$$
KS(-1111,0) = KS(-111,10)
$$

This is enough to mount a keystream-reuse attack.

---

## Turning collisions into plaintext recovery

Let the encrypted flag be produced at `ts_start` and split into blocks:

$$
C^{flag}_j = P^{flag}_j \oplus KS(ts\_start, j)
$$

Now make an `/encrypt` query at a new timestamp `ts_query` and craft a plaintext whose **block at index `i` equals `$C^{flag}_j$`**:

- Prefix with `i` blocks of zero bytes: `00…00` (length `16*i`)
- Then append `$C^{flag}_j$` as the next 16-byte block

So the queried plaintext block is:

$$
P_i = C^{flag}_j
$$

The server returns for that block:

$$
C_i = P_i \oplus KS(ts\_query, i) = C^{flag}_j \oplus KS(ts\_query, i)
$$

If we choose `(ts_query, i)` such that:

$$
\text{str}(ts\_query)\,||\,\text{str}(i) = \text{str}(ts\_start)\,||\,\text{str}(j)
\Rightarrow KS(ts\_query,i)=KS(ts\_start,j)
$$

then:

$$
C_i = C^{flag}_j \oplus KS(ts\_start,j)
     = (P^{flag}_j \oplus KS(ts\_start,j)) \oplus KS(ts\_start,j)
     = P^{flag}_j
$$

**Meaning:** the ciphertext block we get back at position `i` is literally the **plaintext** block of the flag.

---

## A concrete collision plan (with increasing timestamps)

Pick:

- `ts_start = -1111`

Then for flag blocks `j = 0, 1, 2`, one working set of collisions is:

- `j=0`: `"-1111" + "0" = "-11110"` → choose `(ts_query, i)=(-111, 10)`
- `j=1`: `"-1111" + "1" = "-11111"` → choose `(ts_query, i)=(-11, 111)`
- `j=2`: `"-1111" + "2" = "-11112"` → choose `(ts_query, i)=(-1, 1112)`

These query timestamps are strictly increasing:

$$
-1111 < -111 < -11 < -1
$$

so they satisfy the “timestamps must increase” rule.

---

## Attack algorithm

1. Call `/startsession(ts_start)` and receive `(session_id, encrypted_flag)`.
2. Split `encrypted_flag` into 16-byte blocks `Cflag[j]`.
3. For each block `j`:
   - pick a colliding pair `(ts_query, i)` so `str(ts_query)||str(i) == str(ts_start)||str(j)`
   - build `data = (00...00 for 16*i bytes) || Cflag[j]`
   - call `/encrypt(session_id, ts_query, data)`
   - read returned ciphertext block `i` → that equals plaintext block `Pflag[j]`
4. Concatenate recovered blocks and PKCS#7-unpad to get the flag.

---

## Why this design is unsafe (and how to fix it)

### What went wrong

- XOR-based encryption is **malleable** and offers no integrity on its own; it becomes a disaster when keystream reuse is possible.
- The keystream depends on attacker-influenced parameters and is built with ambiguous serialization.

### How to fix it properly

1. **Use AEAD (recommended):**
   - **AES-GCM** (NIST SP 800-38D)
   - **ChaCha20-Poly1305** (RFC 8439)  
   AEAD gives confidentiality *and* integrity, preventing these “oracle” style plaintext recoveries.

2. **If you must hash inputs, encode them unambiguously:**
   - use fixed-width binary encoding (`to_bytes`) and delimit fields
   - never rely on `str(a)+str(b)` for security-relevant domain separation

3. **Don’t let clients choose the nonce/timestamp:**
   - generate nonces server-side and enforce uniqueness



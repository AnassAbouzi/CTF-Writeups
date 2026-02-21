# XTaSy (Crypto) — Securinets CTF Quals 2025

> Primitive: AES-XTS (tweakable blockcipher mode with ciphertext stealing)  
> Vulnerabilities: **malleability + fixed tweak reuse + decryption oracle**

---

## TL;DR

The server encrypts a JSON token using **AES-XTS** with a **single fixed key and tweak** for all tokens in the session. The `check_admin` endpoint decrypts attacker-controlled ciphertext and, if JSON parsing fails, **leaks the decrypted plaintext as hex**.

Using that decryption oracle + XTS’s ciphertext-stealing behavior, we can:
1. Recover the unknown “stolen” suffix bytes,
2. Ask the server to encrypt a chosen block `: 1}` at the right block index,
3. Splice that ciphertext block into a legitimate token at the same block index,
4. Retry until the resulting plaintext is valid JSON with `"admin": 1`.

---

## Challenge interface

The server supports two actions (sent as JSON lines):

- `get_token(u, p)`  
  Returns `token = AES_XTS_encrypt(json.dumps({"username": u, "password": p, "admin": 0}))`

- `check_admin(token)`  
  Decrypts token and runs `json.loads(...)`. If parsing fails, it returns an error that includes the **full decrypted bytes as hex**. On success it returns the flag that we want.

### Relevant server code (simplified)

```python
class AES_XTS:
    def __init__(self):
        self.key = os.urandom(64)   # AES-256-XTS (two 256-bit keys)
        self.tweak = os.urandom(16) # single tweak reused for all tokens

    def encrypt(self, plaintext):
        return Cipher(AES(self.key), XTS(self.tweak)).encryptor().update(
            plaintext.encode("latin-1")
        )

    def decrypt(self, ciphertext):
        return Cipher(AES(self.key), XTS(self.tweak)).decryptor().update(ciphertext)

def get_token(username, password):
    data = {"username": username, "password": password, "admin": 0}
    s = json.dumps(data, ensure_ascii=False)
    return cipher.encrypt(s)

def check_admin(token):
    try:
        s = cipher.decrypt(token)
        data = json.loads(s)
        return data["admin"]
    except:
        print(json.dumps({"error": f'Invalid JSON token "{s.hex()}"'}))
        return None
```

---

## What goes wrong

### 1) XTS provides no integrity (malleable encryption)

AES-XTS is designed for storage encryption. It does **not** authenticate ciphertexts. So changing ciphertext changes plaintext, and the server has no MAC/tag to detect tampering.

### 2) The tweak is reused for every token

In XTS, each block is processed with a per-block “tweak value” derived from the provided tweak and the **block index**. If the server reuses the same tweak for every message, then ciphertext blocks are effectively *position-dependent* but **reusable across messages at the same block index**.

So: take a ciphertext block produced at index `i` in one token and paste it into index `i` of another token → it decrypts to the corresponding plaintext block at index `i`.

### 3) `check_admin` is a decryption oracle

On JSON parse error, the server prints the decrypted plaintext bytes in hex. That gives us a **chosen-ciphertext decryption oracle**, which is extremely powerful in any “encrypt-then-parse” design.

### 4) Ciphertext stealing complicates the last blocks, but also helps

XTS supports ciphertext stealing (CTS) for messages whose length isn’t a multiple of 16 bytes. The last two blocks are “mixed” so the ciphertext length matches the plaintext length without padding.

That means:
- some suffix bytes are “out of our control” when we try to align block boundaries,
- but with the decryption oracle, we can recover those bytes and incorporate them into our crafted plaintext.

---

## Attack strategy

We want a token that decrypts to JSON with `"admin": 1`.

Because we can’t directly set `admin` through `get_token`, we do it by block splicing:

1. **Get a baseline token** with a chosen username/password length that triggers CTS.
2. **Use the decryption oracle** to recover the CTS “suffix” bytes that we can’t control.
3. **Ask the server to encrypt a payload** that contains `: 1}` placed so it lands on the target block index, plus the recovered suffix.
4. **Inject the payload ciphertext block** into the baseline token at the same block index.
5. Submit to `check_admin`. If JSON parsing fails (due to unlucky suffix bytes), repeat.

---

## Concrete exploitation (matching the provided solver)

The included solver uses:

- `username = "61"` → `"a"`
- `password = "61616161616161"` → `"aaaaaaa"`

This yields a JSON plaintext whose total length is not a multiple of 16, so CTS happens.

### Step 1 — obtain an original token

Send:

```json
{"option":"get_token","username":"61","password":"61616161616161"}
```

Save the returned hex string as `original_ct`.

### Step 2 — recover the CTS suffix using the oracle

The solver pads/rearranges the ciphertext to force the server to decrypt and leak bytes that include the CTS-derived suffix:

- Insert an all-zero block,
- Pad to a whole number of blocks,
- Call `check_admin`,
- Extract the leaked plaintext hex from the error message,
- Take the suffix bytes from the relevant block.

(See the `padded_original_ct` and `suffix` extraction in `solution.py`.)

### Step 3 — make the server encrypt our `: 1}` block at the right index

Now that we know the suffix bytes, we can craft an input to `get_token` so that, at the target block index, the plaintext contains:

```
: 1} || suffix || 00 00
```

The solver achieves this by using the **password field as padding** (lots of `"a"` bytes) so that the substring `: 1}` is positioned exactly where it needs to be.

Request:

```json
{"option":"get_token","username":"61","password":"6161616161616161616161616161616161" + " 3a20317d" + suffix + "0000"}
```

Save this new token as `payload_ct`.

### Step 4 — splice the payload block into the original token

Extract the block containing the encrypted `: 1}` payload from `payload_ct`, and replace the corresponding block in `original_ct`.

The solver does:

- `payload_blk = payload_ct[96:128]`
- `payload = original_ct[:64] + payload_blk + original_ct[96:]`

Then calls:

```json
{"option":"check_admin","token":"<payload>"}
```

If the plaintext parses and `admin` is `1`, the server returns the flag.

### Step 5 — retry loop

Sometimes the recovered suffix bytes cause JSON parsing issues (e.g., they can introduce problematic characters). The provided solve script notes this and suggests retrying until a successful parse occurs.

---

## Why this works (intuition)

- **No MAC/tag** → ciphertext is modifiable.
- **Same tweak for all tokens** → block `i` is “compatible” across tokens at index `i`.
- **Decryption oracle** → we can learn the unknown CTS “suffix” bytes and compensate.
- **CTS** → makes the last blocks tricky, but also gives structure to exploit.

---

## Mitigations

To prevent this entire class of attacks:

1. Use an AEAD mode (e.g., AES-GCM or ChaCha20-Poly1305) and reject modified tokens.
2. Never return decrypted plaintext in error messages.
3. If using a tweak/nonce, make it unique per token and include it with the ciphertext (still with authentication).

---

## Files

- `challenge.py` : server logic (AES-XTS token + oracle leak)
- `solution.py` : reference exploit that:
  - queries the oracle to extract the CTS suffix
  - encrypts a payload block via `get_token`
  - splices ciphertext blocks to forge an admin token

---

## References

- XTS mode : https://en.wikipedia.org/wiki/Disk_encryption_theory#XEX-based_tweaked-codebook_mode_with_ciphertext_stealing_(XTS)

# Lightweight (Crypto) — Srdnlen CTF Quals 2026

## Overview

This challenge implements a **round-reduced Ascon initialization phase** and then gives us an **oracle** that for a nonce `N` it returns initialization output for `N` and `N ⊕ Δ`, where we get to choose `Δ`.

With only **4 rounds**, this leaks key bits through a strong, measurable **bias** in certain output difference bits. By repeating queries enough times, we recover almost the entire key **bit by bit**, then brute-force the remaining few bits.

## What the server does
The server code (`server.c`) implements a **custom Ascon permutation**:

State is initialized as state = [ IV, key0, key1, nonce0, nonce1 ] (320 bits total, each element is 64 bits), Then it runs **NROUNDS = 4** rounds of Ascon's permutation (but it uses different round constants), each permutation adds a constant into `state[2]`, applies the sbox (the same as keccak's) then applies the Linear Diffusion Layer.

then the server opens an oracle interface that :
1. Picks a random 128-bit key `(key0, key1)` once.
2. Repeats up to `MAX_QUERIES = 2^16` times:
 - Reads a user-chosen 128-bit XOR difference `Δ = (diff0, diff1)`.
 - Samples a fresh random 128-bit nonce `N = (nonce0, nonce1)` and prints it.
 - Computes and prints:
   - `ascon_k(N)`  (two 64-bit words: `out[0], out[1]`)
   - `askon_k(N ⊕ Δ)` (again `out[0], out[1]`)
3. After you stop (by sending `Δ=0`), it asks you to **guess the key**.

## Solution
Since the server deliberatly provides a chosen difference oracle, the first idea that comes to mind is differential cryptanalysis (these attacks are also common on round-reduced versions of algorithms), the first result that pops up when searching "ascon differential cryptanalysis" is the research paper by Dobraunig et al. "Cryptanalysis of Ascon", section "5.4 Differential-linear cryptanalysis" describes exactly an attack on a 4 rounds initialization phase of ascon in which input differences are ony allowed in the nonce (x3, x4) and we only need to observe the outputs of x0 (`out[0]`), bingo that's exactly our case.
This attack uses a hybride of both differencial and linear cryptanalysis, which is very useful when  the combined success probability of one short differential characteristic and one short linear characteristic is better than the probability of a longer linear or differential characteristic. I won't go into the details of the differential path and linear approximations used (the curious reader can refer to the mentioned paper) because to perform the attack we only need the results (and faith that the authors of the paper know what they are doing). According to the paper sending a bunch of queries with pairs of nonces which have differences in `x3[i]` and `x4[i]` (the `(i+1)th` bit of both nonces) we can calculate a bias of `x0[(i + 1) % 64]` that allows us to infer with good probability the bits of  the keys `k1[i]` and `k2[i]` (approximately $2^{-12}$). 
the mapping of each bit pair to a bias is represented in the followig table :
| inputs (`x1[i]`, `x2[i]`) | key-bit pair |   (0, 0)    |    (0, 1)   |   (1, 0)    |   (1, 1)    |
| :------------------------ | :----------: | :---------: | :---------: | :---------: | ----------: |
|                           |     sign     |     +1      |      -1     |      +1     |      -1     |
|     output `x0[i + 1]`    |     bias     | $2^{-2.68}$ | $2^{-3.68}$ | $2^{-3.30}$ | $2^{-2.30}$ |

Now we present the partical steps of the attack that allowed us to solve the challenge :

### Step 1 : pick a difference `Δ`
For a certain bit position i we send the difference `((1 << i), (1 << i))` (we target the same bit position for both nonce halves), the server then generates a fresh nonce N then compute `ascon(N)` and `ascon(N ⊕ Δ)` and sends the nonce with the results, we store some of these for later verifications.

### Step 2 : “Undoing” the diffusion on output bit i of x0 (`out[0]`)
The values that the server returns `out[0]` and `out[1]` are the outputs of the full permutation, but to compute the bias we need the bits of the output of the last sbox, therefore we have to apply the inverse function that undoes the diffusion layer (the function is linear so we can invert it).

### Step 3 : Compute the bias and recover the key bits
After we get the outputs of the last sbox we XOR them together and observe the bit `(i + 1)` and calculate how many zeros we get, after we've sent all the queries for a certain bit position and received all the outputs we compute the bias :
$$
Bias = \frac{\text{number of zeros}}{\text{number of queries}} - 0.5
$$
After we get the bias we use the values in the table above to recover the key bits by choosing the closest value to the bias.
About 1000 queries per bit should be enough to get the correct bias with a good probability and doesn't surpass the query limit imposed by the server `(64000 < 2**64)`.

### Step 4 : Bruteforcing the remaining 16 bits and ambiguous bits
For some reason when I was testing on my local machine I kept getting wrong results for the lowest byte of each key block, and because we have a limited number of queries I couldn't just increase the probability of success because it was not possible and not very efficient, a more efficient solution is to just brute force the remaining bits along with some ambiguous bits (who's bias had a difference with one of the values in the table that surpassed a certain treshold) using the nonce/output pairs we stored in the first step to validate the correct key

### Step 5 : Submit the key and get the flag
Finally we send `Δ=0` to stop query mode and then we send the recovered `(key0, key1)` as hex and recover the flag.

## Refrences :
Dobraunig, C., Eichlseder, M., Mendel, F., & Schläffer, M. (2015). Cryptanalysis of Ascon (Cryptology ePrint Archive, Paper 2015/030). https://eprint.iacr.org/2015/030

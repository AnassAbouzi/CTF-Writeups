import requests

def unpad(data):
    if len(data) == 0:
        return data
    p = data[-1]
    if p == 0 or p > len(data):
        raise ValueError("Invalid padding")
    if all(x == p for x in data[-p:]):
        return data[:-p]
    raise ValueError("Invalid padding")

url = "https://clandescriptorius.challs.pwnoh.io"

ts_start = -1111
r = requests.post(url + "/startsession", json={'timestamp': ts_start})

data = r.json()
session_id = data['session_id']
encrypted_flag_hex = data['encrypted_flag']
print(f"Session ID: {session_id}")
print(f"Encrypted Flag: {encrypted_flag_hex}")

encrypted_flag_bytes = bytes.fromhex(encrypted_flag_hex)
if len(encrypted_flag_bytes) % 16 != 0:
    print("Invalid encrypted flag length")
    exit(1)

num_blocks = len(encrypted_flag_bytes) // 16

flag_cipher_blocks = [
    encrypted_flag_bytes[i*16:(i+1)*16] for i in range(num_blocks)
]

# Define the splits for each flag block (j, ts_my, i)
# Adjusted from -1001 to -1111 to avoid zeros and allow distinct increasing timestamps
# For block 0: '-111' + '10' = '-11110' -> ts=-111, i=10
# For block 1: '-11' + '111' = '-11111' -> ts=-11, i=111
# For block 2: '-1' + '1112' = '-11112' -> ts=-1, i=1112
splits = [
    (0, -111, 10),
    (1, -11, 111),
    (2, -1, 1112),
]

# Sort by ts_my ascending to ensure increasing timestamps
splits.sort(key=lambda x: x[1])

# Recover plain blocks
plain_blocks = [None] * num_blocks
last_ts = ts_start

for j, ts_my, i in splits:
    if ts_my <= last_ts:
        print("Timestamp not increasing")
        exit(1)

    # Prepare known data: \x00 * (i * 16)
    # Since len % 16 == 0, padding will be \x10 * 16 (16 in decimal)
    data_len = i * 16
    data = b'\x00' * data_len + flag_cipher_blocks[j]
    data_hex = data.hex()

    # Encrypt
    response = requests.post(
        f'{url}/encrypt',
        json={
            'session_id': session_id,
            'data': data_hex,
            'timestamp': ts_my
        }
    )
    if response.status_code != 200:
        print(f"Error encrypting: {response.text}")
        exit(1)

    result = response.json()
    if 'encrypted' not in result:
        print(f"Encryption error: {result.get('detail')}")
        exit(1)

    encrypted_hex = result['encrypted']
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    # Verify length: data_len + 16
    expected_len = data_len + 32
    if len(encrypted_bytes) != expected_len:
        print("Invalid encrypted length")
        exit(1)

    my_cipher_blocks = [
        encrypted_bytes[k*16:(k+1)*16] for k in range(len(encrypted_bytes)//16)
    ]

    plain_j = my_cipher_blocks[i]

    plain_blocks[j] = plain_j

    # Update last_ts
    last_ts = ts_my


# Assemble padded plaintext
padded_plain = b''.join(plain_blocks)

# Unpad
flag_bytes = unpad(padded_plain)

# Decode and print
try:
    flag = flag_bytes.decode('utf-8')
    print(f"Recovered Flag: {flag}")
except UnicodeDecodeError:
    print("Flag is not valid UTF-8")

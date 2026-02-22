import socket
import json
import sys
import hashlib

host = "exclusive.p2.securinets.tn"
port = 6003


#step 1
#recover the first 4 blocks
"""
flag_blk4 = sys.argv[1]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
    s.connect((host, port))
    s.recv(2028)
    blk_num = "4"
    s.sendall(blk_num.encode() + b"\n")
    s.recv(1024)
    r = s.recv(1024).decode().split(":")[1].split("\n")[0].strip()
    enc_flg = r[32:]
    enc_pre = r[:32]
    payload = enc_flg + enc_pre[:-(2 * (len(flag_blk4) + 1))]
    s.sendall(payload.encode() + b"\n")
    s.recv(1024)
    S = s.recv(1024).decode().split(":")[1].split("\n")[0].strip()
    for i in range(int(sys.argv[2]), 0x100) :
        print(i)
        payload = enc_pre[:-(2 * (len(flag_blk4) + 1))] + hex(i)[2:].zfill(2) + flag_blk4.encode().hex()
        s.sendall(payload.encode() + b"\n")
        s.recv(1024)
        r = s.recv(1024).decode().split(":")[1].split("\n")[0].strip()
        if S == r :
            print(f'found the flag byte : {chr(i)}')
"""

#step 2
# recover the last block
"""
flag_blk5 = sys.argv[1]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # Linux / many Unixes:
    if hasattr(socket, 'TCP_KEEPIDLE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    if hasattr(socket, 'TCP_KEEPCNT'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    s.connect((host, port))
    s.recv(2048)
    blk_num = "5"
    s.sendall(blk_num.encode() + b"\n")
    s.recv(2048)
    r = s.recv(2048).decode().split(":")[1].split("\n")[0].strip()
    enc_flg_enc_pre = r[:32]
    enc_pre = r[32:]
    enc = r
    s.sendall(r.encode() + b"\n")
    s.recv(2048)
    pre = s.recv(2048).decode().split(":")[1].split("\n")[0].strip()
    pre_suf = ""
    for i in range(3) :
        for b in range(0x100) :
            print(b)
            print((pre_suf if pre_suf else ""))
            payload = enc + (pre_suf if pre_suf else "") + hex(b)[2:].zfill(2)
            s.sendall(payload.encode() + b"\n")
            s.recv(4096)
            res = s.recv(4096).decode().split(":")[1].split("\n")[0].strip()
            if pre == res :
                pre_suf += (hex(b)[2:].zfill(2))
                print(f"found byte {hex(b)}")
                break
    for b in range(0x100) :
        print(b)
        print((pre_suf if pre_suf else ""))
        payload = enc_pre + (pre_suf if pre_suf else "") + hex(b)[2:].zfill(2)
        s.sendall(payload.encode() + b"\n")
        s.recv(4096)
        res = s.recv(4096).decode().split(":")[1].split("\n")[0].strip()
        if pre == res :
            pre_suf += (hex(b)[2:].zfill(2))
            print(f"found byte {hex(b)}")
            break

    enc_pre = enc_pre + pre_suf
    print(f"found the enc(pre) value :D  : {enc_pre}")


    payload =  enc[:-(2 * (len(flag_blk5) + 1))]
    s.sendall(payload.encode() + b"\n")
    s.recv(2048)
    S = s.recv(2048).decode().split(":")[1].split("\n")[0].strip()
    values = [49, 50, 51, 52, 53, 54, 55, 56, 57, 48,  97, 98, 99, 100, 101, 102, 125]
    #values = [49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 113, 119, 101, 114, 116, 121, 117, 105, 111, 112, 97, 115, 100, 102, 103, 104, 106, 107, 108, 122, 120, 99, 118, 98, 110, 109, 95, 123, 125, 63, 33]
    for i in values :
        payload = enc_pre[:-8 -(2 * (len(flag_blk5) + 1))] + hex(i)[2:].zfill(2) + flag_blk5.encode().hex() + enc_pre[-8:]
        s.sendall(payload.encode() + b"\n")
        s.recv(2048)
        r = s.recv(2048).decode().split(":")[1].split("\n")[0].strip()
        if S == r :
            print(f'found the flag byte : {chr(i)}')
"""


#step 3
#brute force the remaining bytes
flag_blk1 = "Securinets{bd012"
flag_blk2 = "cff0a13e60e4018"
flag_blk3 = "1bcf623195e4992"
flag_blk4 = "25682b32f69d5d1"
flag_blk5 = "cd0b8e00ec}"
target_hash = "f367040067710f493b20a57e97e87fef1b4e4fc8e9c7a858fdab78b75d43a3e0"

values = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", 'A', 'B', 'C', 'D', 'E', 'F', '_', '-', '?', '!']
for i1 in values :
    for i2 in values :
        for i3 in values :
            for i4 in values :
                candidate = flag_blk1 + i1 + flag_blk2 + i2 + flag_blk3 + i3 + flag_blk4 + i4 + flag_blk5
                v = hashlib.sha256(candidate.encode()).hexdigest()
                if v == target_hash :
                    print(f"found flag : {candidate}")
                    break

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dataclasses import dataclass
import os
import hashlib

flag = os.environ.get("FLAG") or "bctf{fake_flag_fake_flag_fake_flag_fake_flag}"


def xor(aa: bytes, bb: bytes):
    return bytes(a ^ b for a, b in zip(aa, bb))


def pad(data: bytes):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)


def encrypt_block(block: bytes, key: bytes, timestamp: int, block_index: int):
    keystream = hashlib.sha256(
        f"{key.hex()}{timestamp}{block_index}".encode()
    ).digest()[0:16]
    return xor(keystream, block)


def encrypt(data: bytes, key: bytes, timestamp: int):
    padded = pad(data)
    blocks = [padded[i : i + 16] for i in range(0, len(padded), 16)]
    return b"".join(
        encrypt_block(block, key, timestamp, i) for i, block in enumerate(blocks)
    )


@dataclass
class Session:
    last_timestamp: int
    key: bytes


sessions: dict[str, Session] = {}


app = FastAPI()


class StartSessionRequest(BaseModel):
    timestamp: int


@app.post("/startsession")
def route_startsession(request: StartSessionRequest):
    session_id = os.urandom(16).hex()
    key = os.urandom(32)
    timestamp = request.timestamp
    encrypted_flag = encrypt(flag.encode(), key, timestamp)
    sessions[session_id] = Session(last_timestamp=timestamp, key=key)
    return {
        "session_id": session_id,
        "encrypted_flag": encrypted_flag.hex(),
    }


class EncryptRequest(BaseModel):
    session_id: str
    timestamp: int
    data: str


@app.post("/encrypt")
def route_encrypt(request: EncryptRequest):
    try:
        session = sessions[request.session_id]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid session id")
    try:
        data = bytes.fromhex(request.data)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex in data")
    if request.timestamp <= session.last_timestamp:
        raise HTTPException(status_code=400, detail="Non-increasing timestamp")
    session.last_timestamp = request.timestamp
    return {"encrypted": encrypt(data, session.key, request.timestamp).hex()}


app.mount("/", StaticFiles(directory="static", html=True), name="static")

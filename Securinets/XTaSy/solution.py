import socket
import json

host = "xtasy.p2.securinets.tn"
port = 6001

username = "61"
password = "61616161616161"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
    s.connect((host, port))
    s.recv(2028)
    """
    first get a ciphertext for the following data
    0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
    { " u s e r n a m e " :   " a " ,   " p a s s w o r d " :   " a a a a a a a " ,   " a d m i n " :   0 }
    """
    request = json.dumps({"option" : "get_token", "username": username, "password" : password})
    s.sendall(request.encode() + b"\n")
    s.recv(2028)
    response = json.loads(s.recv(2028).decode().split("\n")[0])
    original_ct = response["token"]
    """
    The ciphertext we get is C1_C2_C3_C4 with C3 being the encryption of P4+C3'[len(P) % 16:] (ciphertext stealing)
    we are then going to pad it to get 5 full blocks and place C3 as the 4th block (to decrypt it using the same tweak used to encrypt it)
    0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
    c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 c c c c c c c c c c c c c c c c c c c c 0 0 0 0 0 0 0 0 0 0 0 0
    by decrypting this cipher text we get the value P4 + C3'[len(P) % 16:] as the third block of the decryption
    """
    padded_original_ct = original_ct[:64] + "0" * 32 + original_ct[64:] + "0" * (32 - (len(original_ct) % 32))
    request = json.dumps({"option": "check_admin", "token": padded_original_ct})
    s.sendall(request.encode() + b"\n")
    s.recv(2048)
    """
    the decryption oracle we use is the try catch block for json data in the check admin function
    we then extract the the C3'[len(P) % 16:] value (sufix) and use it to get the encryption of the payload :
    0 1 2 3 4 5 6 7 8 9 a b c d e f
    :   1 } + suffix
    """
    response = s.recv(2048).decode().split("\\")[1][1:]
    second_last_blk = response[-64:-32]
    suffix = second_last_blk[8:]
    """
    this time we use the password value as a pad to place the payload on the 4th block to encrypt it using the correct tweak
    0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
    { " u s e r n a m e " :   " a " ,   " p a s s w o r d " :   " a a a a a a a a a a a a a a a a a :   1 } s s s s s s s s s s s s 0 0 " ,   " a d m i n " :   0 }
    we should note that we can't control the value of the sufix bytes so the values s might be characteres that get escaped so we should just keep trying until the
    attack works, there are 34 bytes out of 256 that are escaped by json.dumps(x, ensure_ascii=False) so the probability of success of the 
    attack is approximatly (1 - (34 / 256))**12 = 0.19 so 1 in 10 tries should get you the flag
    """
    padding_pwd = "61616161616161616161616161616161613a20317d" + suffix + "00" * 2
    request = json.dumps({"option" : "get_token", "username": username, "password" : padding_pwd})
    s.sendall(request.encode() + b"\n")
    s.recv(2028)
    response = json.loads(s.recv(2028).decode().split("\n")[0])
    payload_ct = response["token"]
    print(payload_ct)
    print(len(payload_ct))
    """
    after getting the encrypted payload we simply replace the 3rd block in the original token by our payload (we use 3rd and not 4th because of ciphertext stealing)
    """
    payload_blk = payload_ct[96:128]
    payload = original_ct[:64] + payload_blk + original_ct[96:]
    request = json.dumps({"option": "check_admin", "token": payload})
    s.sendall(request.encode() + b"\n")
    s.recv(2048)
    response = s.recv(2048).decode()
    print(response)

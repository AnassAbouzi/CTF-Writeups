import socket

host = "exclusive.p2.securinets.tn"
port = 6003


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
    s.connect((host, port))
    s.recv(2028)
    s.sendall("1".encode() + b"\n")
    s.recv(1024)
    r = s.recv(1024).decode().split(":")[1].split("\n")[0].strip()
    for i in range(256) :
        print(i)
        s.sendall(r.encode() + b"\n")
        s.recv(1024)
        S = s.recv(1024).decode().split(":")[1].split("\n")[0].strip()

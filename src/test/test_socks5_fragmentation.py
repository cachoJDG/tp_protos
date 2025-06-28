import socket
import time

# Hecho con IA (revisar si es correcto)

def send_fragmented(sock, data, fragment_size=1, delay=0.1):
    """Send data in tiny fragments with delays between each send."""
    for i in range(0, len(data), fragment_size):
        fragment = data[i:i+fragment_size]
        sock.send(fragment)
        print(f"Sent fragment: {fragment.hex()}")
        time.sleep(delay)

# SOCKS5 proxy details
proxy_host = "127.0.0.1"
proxy_port = 2021
username = b"jhon"  # Note: your hashmap contains "john" not "jhon"
password = b"doe"

# Connect to the proxy
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((proxy_host, proxy_port))
print(f"Connected to proxy at {proxy_host}:{proxy_port}")

# 1. Authentication method negotiation - FRAGMENTED
auth_request = b"\x05\x01\x02"  # SOCKS5, 1 auth method, username/password auth
print("Sending auth negotiation request...")
send_fragmented(s, auth_request, fragment_size=1, delay=0.2)

# Receive auth method response
resp = s.recv(2)
print(f"Auth method response: {resp.hex()}")
if resp[1] != 2:  # 2 is username/password auth
    print(f"Error: Proxy did not select username/password auth, got {resp[1]}")
    s.close()
    exit(1)

# 2. Username/password authentication - FRAGMENTED
auth_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
print("Sending username/password auth...")
send_fragmented(s, auth_data, fragment_size=1, delay=0.2)

# Receive auth result
auth_resp = s.recv(2)
print(f"Auth result: {auth_resp.hex()}")
if auth_resp[1] != 0:
    print("Authentication failed!")
    s.close()
    exit(1)

# 3. Connection request to example.org:80 - FRAGMENTED
dest_host = b"example.org"
dest_port = 80
conn_request = b"\x05\x01\x00\x03" + bytes([len(dest_host)]) + dest_host + dest_port.to_bytes(2, 'big')
print("Sending connection request...")
send_fragmented(s, conn_request, fragment_size=1, delay=0.2)

# Receive connection response
conn_resp = s.recv(10)  # Response length varies based on address type
print(f"Connection response: {conn_resp.hex()}")
if conn_resp[1] != 0:
    print(f"Connection failed with error code: {conn_resp[1]}")
    s.close()
    exit(1)

# 4. Now send an actual HTTP request
http_request = f"GET / HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n".encode()
print("Sending HTTP request...")
send_fragmented(s, http_request, fragment_size=10, delay=0.1)  # Larger fragments for HTTP

# Receive and print HTTP response (just first chunk)
print("Waiting for HTTP response...")
http_resp = s.recv(4096)
print(f"HTTP response first {len(http_resp)} bytes:")
print(http_resp.decode('utf-8', errors='ignore')[:200] + "...")

s.close()
print("Connection closed")
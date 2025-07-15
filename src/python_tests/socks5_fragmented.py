import socket
import time
import sys

# TODO: delete

def send_fragmented(sock, data, fragment_size=1, delay=0.1):
    """Send data in tiny fragments with delays between each send."""
    for i in range(0, len(data), fragment_size):
        fragment = data[i:i+fragment_size]
        sock.send(fragment)
        print(f"Sent fragment: {fragment.hex()}")
        time.sleep(delay)

def main():
    # SOCKS5 proxy details
    proxy_host = "127.0.0.1"
    proxy_port = 2021
    username = b"john_doe"
    password = b"1234"
    target_host = "example.org"
    target_port = 80
    
    # Connect to the proxy
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((proxy_host, proxy_port))
    print(f"Connected to proxy at {proxy_host}:{proxy_port}")
    
    # 1. Authentication method negotiation - FRAGMENTED
    print("\n[Step 1] Sending auth negotiation request (FRAGMENTED)...")
    auth_request = b"\x05\x01\x02"  # SOCKS5, 1 auth method, username/password auth
    # auth_request = b"\x05\x01\x04"  # SOCKS5, 0x04 unvalid auth method
    send_fragmented(s, auth_request, fragment_size=1, delay=0.2)
    
    # Receive auth method response
    resp = s.recv(2)
    print(f"Auth method response: {resp.hex()}")
    
    # 2. Username/password authentication - FRAGMENTED
    print("\n[Step 2] Sending username/password auth (FRAGMENTED)...")
    # Format: version(1) + username_len(1) + username + password_len(1) + password
    auth_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    send_fragmented(s, auth_data, fragment_size=1, delay=0.2)
    
    # Receive auth result
    auth_resp = s.recv(2)
    print(f"Auth result: {auth_resp.hex()}")
    
    # 3. Connection request - FRAGMENTED
    print("\n[Step 3] Sending connection request (FRAGMENTED)...")
    # Format: ver(1) + cmd(1) + rsv(1) + atyp(1) + dst.addr(var) + dst.port(2)
    conn_request = b"\x05\x01\x00\x03\x00" + bytes([len(target_host)]) + target_host.encode() + target_port.to_bytes(2, 'big')
    send_fragmented(s, conn_request, fragment_size=1, delay=0.2)
    
    # Receive connection response
    conn_resp = s.recv(10)
    print(f"Connection response: {conn_resp.hex()}")
    
    # 4. Send HTTP request - FRAGMENTED
    print("\n[Step 4] Sending HTTP request (FRAGMENTED)...")
    http_request = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
    send_fragmented(s, http_request, fragment_size=5, delay=0.1)
    
    # Receive and print HTTP response 
    print("\n[Step 5] HTTP response:")
    response = b""
    while True:
        try:
            data = s.recv(4096)
            if not data:
                break
            response += data
            print(f"Received {len(data)} bytes")
        except socket.timeout:
            break
    
    # Print first 200 chars of response
    print("\nResponse preview:")
    print(response.decode('utf-8', errors='ignore')[:200] + "...")
    
    s.close()
    print("\nConnection closed")

if __name__ == "__main__":
    main()
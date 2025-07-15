import socket
import time


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
    
    # COMBINED MESSAGE: Send auth negotiation + username/password in one packet
    print("\n[Step 1+2] Sending combined auth negotiation + credentials...")
    
    # Part 1: Auth negotiation (0x05 0x01 0x02)
    # Part 2: Username/password (0x01 + len(username) + username + len(password) + password)
    combined_auth = (
        b"\x05\x01\x02"  # Auth method negotiation
        b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password  # Credentials
    )
    
    s.send(combined_auth)
    print(f"Sent combined auth data: {combined_auth.hex()}")
    
    # Need to receive both responses (one for method negotiation, one for auth)
    auth_method_resp = s.recv(2)
    print(f"Auth method response: {auth_method_resp.hex()}")
    
    auth_result = s.recv(2)
    print(f"Auth result: {auth_result.hex()}")
    
    # 3. Connection request
    print("\n[Step 3] Sending connection request...")
    conn_request = b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host.encode() + target_port.to_bytes(2, 'big')
    s.send(conn_request)
    print(f"Sent connection request: {conn_request.hex()}")
    
    # Receive connection response
    conn_resp = s.recv(10)
    print(f"Connection response: {conn_resp.hex()}")
    
    # 4. Send HTTP request
    print("\n[Step 4] Sending HTTP request...")
    http_request = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
    s.send(http_request)
    print(f"Sent HTTP request ({len(http_request)} bytes)")
    
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
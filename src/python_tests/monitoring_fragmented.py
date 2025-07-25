#!/usr/bin/env python3
"""
Simple fragmented test for monitoring server
Usage: python3 test_monitoring_fragmented.py [port]
"""

import socket
import time
import sys
import struct # Importar para manejar la conversión de bytes

def read_server_response(s):
    """
    Reads a server response, handling the 2-byte length prefix.
    Returns the decoded response string or None on error/closure.
    """
    # Leer los primeros 2 bytes para obtener la longitud
    len_bytes = s.recv(2)
    if not len_bytes:
        print("Server closed connection or no length bytes received.")
        return None
    if len(len_bytes) < 2:
        print(f"Received less than 2 bytes for length: {len_bytes.hex()}")
        return None

    # Convertir de network byte order (big endian) a host byte order
    # !H significa network byte order (big-endian), unsigned short (2 bytes)
    bytes_to_read = struct.unpack('!H', len_bytes)[0]

    if bytes_to_read == 0:
        return "Respuesta vacía del servidor\n"

    # Leer el resto del mensaje
    full_response = b""
    while len(full_response) < bytes_to_read:
        chunk = s.recv(bytes_to_read - len(full_response))
        if not chunk:
            print("Server closed connection or no data received for response body.")
            return None
        full_response += chunk
    
    return full_response.decode('utf-8', errors='ignore')

def send_fragmented(sock, data, fragment_size=1, delay=0.1):
    """Send data in tiny fragments with delays between each send."""
    print(f"Sending {len(data)} bytes fragmented (size={fragment_size}, delay={delay}s)")
    for i in range(0, len(data), fragment_size):
        fragment = data[i:i+fragment_size]
        sock.send(fragment)
        print(f"  Fragment: {fragment.hex()}")
        time.sleep(delay)

def login_and_command_fragmented(port, command_data, command_name):
    """Login and execute one command, both fragmented"""
    print(f"\n[TEST] {command_name} (FRAGMENTED)")
    print("-" * 40)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    
    # 1. Login fragmented
    print("Step 1: Login fragmented...")
    username = b"admin"
    password = b"admin"
    login_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    send_fragmented(s, login_data, fragment_size=1, delay=0.1)
    
    # Get login response (always 2 bytes: status + result)
    login_resp = s.recv(2) # Only read 2 bytes for login response
    print(f"Login response: {login_resp.hex()}")
    if len(login_resp) == 2 and login_resp[1] == 1:
        print("Login SUCCESS")
    else:
        print("Login FAILED or incomplete response")
        s.close()
        return False
    
    # 2. Command fragmented
    print(f"Step 2: {command_name} fragmented...")
    send_fragmented(s, command_data, fragment_size=1, delay=0.1)
    
    # Get command response using the helper function
    try:
        resp_content = read_server_response(s)
        if resp_content is None:
            print(f"Error receiving {command_name} response: Connection closed or invalid data.")
            success = False
        else:
            print(f"{command_name} response: {resp_content}")
            success = True
    except Exception as e:
        print(f"Error receiving {command_name} response: {e}")
        success = False
    
    s.close()
    return success

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    print(f"FRAGMENTED TEST - Monitoring Server Port {port}")
    print("=" * 60)
    print("Testing fragmented login + command for each operation")
    print("Each test: connect -> login -> command -> disconnect")
    
    # Test commands (correct numbering)
    tests = [
        (b"\x01", "LIST_USERS"),           # Command 1
        (b"\x02\x08testuser\x08testpass", "ADD_USER"),  # Command 2
        (b"\x01", "LIST_USERS_AGAIN"),     # Command 1 (verify user added)
        (b"\x04\x08testuser\x07newpass", "CHANGE_PASSWORD"),  # Command 4
        (b"\x05", "GET_METRICS"),          # Command 5
        (b"\x03\x08testuser", "REMOVE_USER"),  # Command 3
        (b"\x01", "LIST_USERS_FINAL"),     # Command 1 (verify user removed)
    ]
    
    success_count = 0
    total_tests = len(tests)
    
    for command_data, command_name in tests:
        if login_and_command_fragmented(port, command_data, command_name):
            success_count += 1
        time.sleep(0.5)  # Pause between tests
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("SUCCESS: All fragmented tests passed!")
        print("Buffer handles fragmentation correctly")
    else:
        print("FAILURE: Some tests failed")
        print("Check server logs for errors")

if __name__ == "__main__":
    main()
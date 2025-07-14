#!/usr/bin/env python3
"""
Test monitoring server with combined messages (potential buffer issues)
Usage: python3 test_monitoring_combined.py [port]
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

def login_and_command_combined(port, command_data, command_name):
    """Send login + command in one packet"""
    print(f"\n[TEST] {command_name} (COMBINED)")
    print("-" * 40)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    
    # Prepare login data
    username = b"admin"
    password = b"admin"
    login_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    
    # Combine login + command in one packet
    combined_data = login_data + command_data
    print(f"Sending combined data: {combined_data.hex()}")
    s.send(combined_data)
    
    # Get login response (always 2 bytes: status + result)
    login_resp = s.recv(2) # Only read 2 bytes for login response
    print(f"Login response: {login_resp.hex()}")
    if len(login_resp) == 2 and login_resp[1] == 1:
        print("Login SUCCESS")
    else:
        print("Login FAILED or incomplete response")
        s.close()
        return False
    
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

def test_multiple_commands_in_packet(port):
    """Test sending multiple complete login+command sequences in one packet.
    Expects server to process only the first sequence and then close."""
    print(f"\n[TEST] MULTIPLE LOGIN+COMMAND SEQUENCES")
    print("-" * 50)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    
    username = b"admin"
    password = b"admin"
    login_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    
    # Create multiple login+command sequences
    sequence1_cmd = b"\x01"  # LIST_USERS
    sequence2_cmd = b"\x05"  # GET_METRICS
    
    # Combine login + command for sequence 1, then login + command for sequence 2
    # The server is expected to process only the first full sequence and close.
    mega_packet = login_data + sequence1_cmd + login_data + sequence2_cmd
    print(f"Sending mega packet with 2 login+command sequences: {mega_packet.hex()}")
    s.send(mega_packet)
    
    success = False
    try:
        # Expect login response for the first sequence (2 bytes)
        login_resp1 = s.recv(2)
        print(f"Login response 1: {login_resp1.hex()}")
        if not (len(login_resp1) == 2 and login_resp1[1] == 1):
            print("Login 1 FAILED or incomplete response")
            return False

        # Expect command response for the first sequence
        cmd_resp1 = read_server_response(s)
        print(f"Command response 1: {cmd_resp1}")
        if cmd_resp1 is None: # Connection closed prematurely or error
            print("Command 1 response FAILED or connection closed.")
            return False
        
        # After the first command, the server is expected to close the connection.
        # Try to read more to confirm closure.
        remaining_data = s.recv(1) # Try to read 1 byte, should be empty if closed
        if not remaining_data:
            print("Server closed connection gracefully as expected after first sequence.")
            success = True
        else:
            print(f"Unexpected data received after first sequence: {remaining_data.hex()}")
            success = False

    except ConnectionResetError: # Catch this specific error as a success condition
        print("Server reset connection as expected after first sequence.")
        success = True
    except Exception as e:
        print(f"Error during multiple sequences test: {e}")
        success = False
    finally:
        s.close()
    return success

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    print(f"COMBINED MESSAGES TEST - Monitoring Server Port {port}")
    print("=" * 60)
    print("Testing combined login+command in single packets")
    print("This tests buffer handling of multiple messages")
    
    # Test individual combined messages
    tests = [
        (b"\x01", "LIST_USERS"),           # Command 1
        (b"\x02\x08testuser\x08testpass", "ADD_USER"),  # Command 2
        (b"\x01", "LIST_USERS_VERIFY"),    # Command 1
        (b"\x05", "GET_METRICS"),          # Command 5
        (b"\x03\x08testuser", "REMOVE_USER"),  # Command 3
    ]
    
    success_count = 0
    total_tests = len(tests) + 1  # +1 for multiple sequences test
    
    for command_data, command_name in tests:
        if login_and_command_combined(port, command_data, command_name):
            success_count += 1
        time.sleep(0.3)
    
    # Test multiple sequences in one packet
    if test_multiple_commands_in_packet(port):
        success_count += 1
        print("Multiple sequences test: SUCCESS")
    else:
        print("Multiple sequences test: FAILED")
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("SUCCESS: All combined message tests passed!")
        print("Buffer handles combined messages correctly")
    else:
        print("FAILURE: Some tests failed")
        print("Buffer may have issues with combined messages")

if __name__ == "__main__":
    main()
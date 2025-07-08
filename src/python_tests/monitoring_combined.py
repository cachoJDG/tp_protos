#!/usr/bin/env python3
"""
Test monitoring server with combined messages (potential buffer issues)
Usage: python3 test_monitoring_combined.py [port]
"""

import socket
import time
import sys

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
    
    # Get login response
    login_resp = s.recv(10)
    print(f"Login response: {login_resp.hex()}")
    if len(login_resp) >= 2 and login_resp[1] == 1:
        print("Login SUCCESS")
    else:
        print("Login FAILED")
        s.close()
        return False
    
    # Get command response
    try:
        resp = s.recv(1024)
        print(f"{command_name} response: {resp.decode('utf-8', errors='ignore')}")
        success = True
    except Exception as e:
        print(f"Error receiving {command_name} response: {e}")
        success = False
    
    s.close()
    return success

def test_multiple_commands_in_packet(port):
    """Test sending multiple complete login+command sequences in one packet"""
    print(f"\n[TEST] MULTIPLE LOGIN+COMMAND SEQUENCES")
    print("-" * 50)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    
    username = b"admin"
    password = b"admin"
    login_data = b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
    
    # Create multiple login+command sequences
    sequence1 = login_data + b"\x01"  # LOGIN + LIST_USERS
    sequence2 = login_data + b"\x05"  # LOGIN + GET_METRICS
    
    # Send both sequences in one packet
    mega_packet = sequence1 + sequence2
    print(f"Sending mega packet with 2 login+command sequences: {mega_packet.hex()}")
    s.send(mega_packet)
    
    # Try to receive all responses
    responses = []
    for i in range(4):  # 2 login responses + 2 command responses
        try:
            resp = s.recv(1024)
            responses.append(resp)
            print(f"Response {i+1}: {resp.hex()} -> {resp.decode('utf-8', errors='ignore')[:50]}...")
        except Exception as e:
            print(f"Error receiving response {i+1}: {e}")
            break
    
    s.close()
    if len(responses) == 2:  # Solo primera secuencia completa
        print("Expected behavior: Server closes after first sequence")
        return True
    else:
        return False

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

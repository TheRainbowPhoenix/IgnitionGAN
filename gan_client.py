# File: gan_client.py

import socket
import ssl
import threading
import time
import hashlib
import base64
import os
import struct
import json

from metroparser import ProtocolHeader, OpCodes

# --- CONFIGURATION ---
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8088  # Use 8088 for default non-SSL, 8060 for SSL
USE_SSL = False  # Change to True to connect to a default SSL-enabled Gateway

# Our client's identity
CLIENT_NAME = "python-gan-client"
CLIENT_UUID = "58a5e5bb-a8c3-4e87-a299-297f645c279c"  # str(uuid.uuid4())
CLIENT_URL = "http://localhost:5088/system"  # A dummy URL for our client


class GANClient:
    def __init__(self, host, port, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.socket = None
        self.is_connected = False
        self.message_id_counter = 0

    def connect(self):
        """Establishes the TCP or SSL socket connection."""
        try:
            print(f"[CLIENT] Connecting to {self.host}:{self.port}...")
            if self.use_ssl:
                # Create SSL context
                context = ssl.create_default_context()
                # In a real scenario, you'd configure certificate verification
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Create regular socket first
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Wrap with SSL
                self.socket = context.wrap_socket(sock, server_hostname=self.host)
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.socket.connect((self.host, self.port))
            self.is_connected = True
            print("[CLIENT] TCP Connection established.")
            return True
        except Exception as e:
            print(f"[CLIENT] Connection failed: {e}")
            return False

    def _do_websocket_handshake(self):
        """Sends the HTTP Upgrade request and validates the server's response."""
        # 1. Generate a random key for the handshake
        key = base64.b64encode(os.urandom(16)).decode('utf-8')

        # 2. Construct the HTTP GET request
        path = f"/system/ws-control-servlet?name={CLIENT_NAME}&uuid={CLIENT_UUID}&url={CLIENT_URL}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )

        print("[CLIENT] Sending WebSocket handshake request...")
        self.socket.send(request.encode('utf-8'))

        # 3. Read and validate the server's response
        response = self.socket.recv(1024).decode('utf-8')
        response_lines = response.split('\r\n')
        response_line = response_lines[0]
        
        if "101" not in response_line:
            print(f"[CLIENT] Handshake failed! Server response: {response_line}")
            return False

        # 4. Validate the Sec-WebSocket-Accept key
        headers = {}
        for line in response_lines[1:]:
            if ':' in line:
                key_header, value = line.split(':', 1)
                headers[key_header.strip().lower()] = value.strip()

        magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_key = key + magic_string
        accept_hash = hashlib.sha1(accept_key.encode('utf-8')).digest()
        expected_accept = base64.b64encode(accept_hash).decode('utf-8')

        if headers.get('sec-websocket-accept') != expected_accept:
            print("[CLIENT] Handshake failed! Invalid Sec-WebSocket-Accept key.")
            return False

        print("[CLIENT] WebSocket Handshake successful.")
        return True

    def _read_websocket_frame(self, text_mode=False):
        """Reads a single server-to-client (unmasked) frame."""
        try:
            # Read first 2 bytes
            header_bytes = self._recv_all(2)
            if not header_bytes or len(header_bytes) < 2:
                return None

            b1, b2 = header_bytes[0], header_bytes[1]
            opcode = b1 & 0x0F

            # Gracefully handle CLOSE frames sent by the server
            if opcode == 0x8:  # Opcode 8 is a CLOSE frame
                payload_len = b2 & 0x7F
                if payload_len == 126:
                    extended_payload_len = self._recv_all(2)
                    payload_len = struct.unpack("!H", extended_payload_len)[0]
                elif payload_len == 127:
                    extended_payload_len = self._recv_all(8)
                    payload_len = struct.unpack("!Q", extended_payload_len)[0]
                
                if payload_len > 0:
                    payload_data = self._recv_all(payload_len)
                    if len(payload_data) >= 2:
                        status_code = struct.unpack("!H", payload_data[:2])[0]
                        reason = payload_data[2:].decode('utf-8')
                        print(f"[CLIENT] Received WebSocket CLOSE frame. Status: {status_code}, Reason: {reason}")
                else:
                    print("[CLIENT] Received WebSocket CLOSE frame.")
                return None  # Signal to the run loop to terminate

            # Read payload length
            payload_len = b2 & 0x7F
            if payload_len == 126:
                extended_payload_len = self._recv_all(2)
                payload_len = struct.unpack("!H", extended_payload_len)[0]
            elif payload_len == 127:
                extended_payload_len = self._recv_all(8)
                payload_len = struct.unpack("!Q", extended_payload_len)[0]

            # Read payload data
            payload_bytes = self._recv_all(payload_len)
            
            if text_mode:
                return payload_bytes.decode('utf-8')
            else:
                return payload_bytes
                
        except Exception as e:
            print(f"[CLIENT] Error reading WebSocket frame: {e}")
            return None

    def _recv_all(self, length):
        """Helper method to receive exactly 'length' bytes."""
        data = b""
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _send_websocket_frame(self, payload_data, is_binary=True):
        """Sends a client-to-server (masked) frame."""
        if isinstance(payload_data, str):
            payload_bytes = payload_data.encode('utf-8')
        else:
            payload_bytes = payload_data
            
        payload_len = len(payload_bytes)
        opcode = 0x2 if is_binary else 0x1  # Binary or Text frame
        header = bytearray()

        # FIN bit + opcode
        header.append(0x80 | opcode)

        # Payload length
        if payload_len <= 125:
            header.append(0x80 | payload_len)  # MASK bit set
        elif payload_len <= 65535:
            header.append(0x80 | 126)  # MASK bit set
            header.extend(struct.pack("!H", payload_len))
        else:
            header.append(0x80 | 127)  # MASK bit set
            header.extend(struct.pack("!Q", payload_len))

        # Generate masking key
        masking_key = os.urandom(4)
        header.extend(masking_key)

        # Mask the payload
        masked_payload = bytearray()
        for i in range(payload_len):
            masked_payload.append(payload_bytes[i] ^ masking_key[i % 4])

        # Send the frame
        try:
            self.socket.send(header + masked_payload)
        except Exception as e:
            print(f"[CLIENT] Error sending WebSocket frame: {e}")

    def run(self):
        """The main client loop."""
        if not self.connect() or not self._do_websocket_handshake():
            self.disconnect()
            return

        try:
            # First, wait for the server's internal handshake
            print("[CLIENT] Waiting for internal handshake from server...")
            internal_handshake = self._read_websocket_frame(text_mode=True)
            if internal_handshake and "remoteConnectionId" in internal_handshake:
                print(f"[CLIENT] Received internal handshake: {repr(internal_handshake)}")
            elif internal_handshake is None:
                return
            else:
                raise Exception("Did not receive valid internal handshake.")

            # Phase 2: Complete the two-way handshake by sending our own ID back.
            our_handshake_message = f"remoteConnectionId={CLIENT_NAME}"
            self._send_websocket_frame(our_handshake_message, is_binary=False)
            print("[CLIENT] Sent our identity back to the server.")

            # Main PING/PONG loop
            while self.is_connected:
                # Send a PING
                self.message_id_counter += 1
                ping_header = ProtocolHeader()
                ping_header.message_id = self.message_id_counter
                ping_header.opcode = OpCodes.PING
                ping_header.sender_id = CLIENT_NAME

                print(f"[CLIENT] Sending PING: {repr(ping_header)}")
                self._send_websocket_frame(ping_header.encode(), is_binary=True)

                # Wait for the PONG (ACK)
                response_frame = self._read_websocket_frame(text_mode=False)
                if response_frame:
                    response_header = ProtocolHeader.decode(response_frame)
                    if response_header.opcode == OpCodes.OK and response_header.message_id == self.message_id_counter:
                        print(f"[CLIENT] Received PONG (ACK): {repr(response_header)}")
                    else:
                        print(f"[CLIENT] Received unexpected response: {repr(response_header)}")
                        print(repr(response_frame))

                time.sleep(10)  # Ping every 10 seconds

        except Exception as e:
            print(f"[CLIENT] Error in run loop: {e}")
        finally:
            self.disconnect()

    def disconnect(self):
        self.is_connected = False
        if self.socket:
            try:
                # Send close frame
                close_frame = bytearray([0x88, 0x00])  # FIN + CLOSE opcode, no payload
                self.socket.send(close_frame)
            except:
                pass
            self.socket.close()
        print("[CLIENT] Disconnected.")


# --- HOW TO RUN ---
if __name__ == "__main__":
    client = GANClient(GATEWAY_HOST, GATEWAY_PORT, USE_SSL)
    # Run the client in a separate thread so it doesn't block
    client_thread = threading.Thread(target=client.run)
    client_thread.daemon = True
    client_thread.start()

    # Keep the main script alive to see the output
    try:
        while client_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping client...")
        client.disconnect()
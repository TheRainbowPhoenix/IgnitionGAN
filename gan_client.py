# File: gan_client.py

from java.net import Socket
from java.lang import Thread, Runnable
import threading
import time
import hashlib
import base64
import os
import uuid
import random
import string

from java.io import InputStreamReader, BufferedReader
from jarray import array as jarray

# Import our parser from the separate file
from metroparser import ProtocolHeader, OpCodes

# --- CONFIGURATION ---
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8088  # Use 8088 for default non-SSL, 8060 for SSL
USE_SSL = False  # Change to True to connect to a default SSL-enabled Gateway

# Our client's identity
CLIENT_NAME = "python-gan-client"
CLIENT_UUID = "58a5e5bb-a8c3-4e87-a299-297f645c279c" # str(uuid.uuid4())
CLIENT_URL = "http://localhost:1234/system"  # A dummy URL for our client


class GANClient(Runnable):
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
            print("[CLIENT] Connecting to %s:%d..." % (self.host, self.port))
            if self.use_ssl:
                # In a real scenario, you'd configure a TrustStore for SSL
                factory = javax.net.ssl.SSLSocketFactory.getDefault()
                self.socket = factory.createSocket(self.host, self.port)
            else:
                self.socket = Socket(self.host, self.port)
            self.is_connected = True
            print("[CLIENT] TCP Connection established.")
            return True
        except Exception as e:
            print("[CLIENT] Connection failed:", e)
            return False

    def _do_websocket_handshake(self):
        """Sends the HTTP Upgrade request and validates the server's response."""
        # 1. Generate a random key for the handshake
        key = base64.b64encode(os.urandom(16))

        # 2. Construct the HTTP GET request
        path = "/system/ws-control-servlet?name=%s&uuid=%s&url=%s" % (CLIENT_NAME, CLIENT_UUID, CLIENT_URL)
        request = (
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s:%d\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Key: %s\r\n"
                      "Sec-WebSocket-Version: 13\r\n"
                      "\r\n"
                  ) % (path, self.host, self.port, key)

        print("[CLIENT] Sending WebSocket handshake request...")
        self.socket.getOutputStream().write(request.encode('utf-8'))
        self.socket.getOutputStream().flush()

        # 3. Read and validate the server's response
        reader = BufferedReader(InputStreamReader(self.socket.getInputStream()))
        response_line = reader.readLine()
        if "101" not in response_line:
            print("[CLIENT] Handshake failed! Server response:", response_line)
            return False

        # 4. Validate the Sec-WebSocket-Accept key
        headers = {}
        while True:
            line = reader.readLine()
            if not line: break
            parts = line.split(":", 1)
            if len(parts) == 2: headers[parts[0].strip().lower()] = parts[1].strip()

        magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected_accept = base64.b64encode(hashlib.sha1(key + magic_string).digest())

        if headers.get('sec-websocket-accept') != expected_accept:
            print("[CLIENT] Handshake failed! Invalid Sec-WebSocket-Accept key.")
            return False

        print("[CLIENT] WebSocket Handshake successful.")
        return True

    def _read_websocket_frame(self, text_mode=False):
        """Reads a single server-to-client (unmasked) frame."""
        instream = self.socket.getInputStream()
        b1 = instream.read()
        if b1 == -1: return None

        opcode = b1 & 0x0F

        # Gracefully handle CLOSE frames sent by the server
        if opcode == 0x8:  # Opcode 8 is a CLOSE frame
            b2 = instream.read()
            payload_len = b2 & 0x7F
            status_code = (instream.read() << 8) | instream.read()
            reason = "".join([chr(instream.read()) for _ in range(payload_len - 2)])
            print("[CLIENT] Received WebSocket CLOSE frame. Status: %d, Reason: %s" % (status_code, reason))
            return None  # Signal to the run loop to terminate

        b2 = instream.read()
        if b2 == -1: return None

        payload_len = b2 & 0x7F
        if payload_len == 126: payload_len = (instream.read() << 8) | instream.read()
        # simplified, assumes no huge frames

        payload_bytes = "".join([chr(instream.read()) for _ in range(payload_len)])

        return payload_bytes.decode('utf-8') if text_mode else payload_bytes

    def _send_websocket_frame(self, payload_bytes, is_binary=True):
        """Sends a client-to-server (masked) frame."""
        payload_len = len(payload_bytes)
        opcode = 0x2 if is_binary else 0x1
        header = [0x80 | opcode]

        if payload_len <= 125:
            header.append(0x80 | payload_len)
        elif payload_len <= 65535:
            header.append(0x80 | 126)
            header.append((payload_len >> 8) & 0xFF)
            header.append(payload_len & 0xFF)

        masking_key = os.urandom(4)
        header.extend(map(ord, masking_key))

        masked_payload = [ord(payload_bytes[i]) ^ ord(masking_key[i % 4]) for i in range(payload_len)]

        signed_header = [b - 256 if b > 127 else b for b in header]
        signed_payload = [b - 256 if b > 127 else b for b in masked_payload]

        # Create the true Java byte[] arrays
        java_header = jarray(signed_header, 'b')
        java_payload = jarray(signed_payload, 'b')

        self.socket.getOutputStream().write(java_header)
        self.socket.getOutputStream().write(java_payload)

        self.socket.getOutputStream().flush()

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
                print("[CLIENT] Received internal handshake:", repr(internal_handshake))
            elif internal_handshake is None:
                return
            else:
                raise Exception("Did not receive valid internal handshake.")

            # Phase 2: Complete the two-way handshake by sending our own ID back.
            our_handshake_message = "remoteConnectionId=%s" % CLIENT_NAME
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

                print("[CLIENT] Sending PING:", repr(ping_header))
                self._send_websocket_frame(ping_header.encode(), is_binary=True)

                # Wait for the PONG (ACK)
                response_frame = self._read_websocket_frame(text_mode=False)
                if response_frame:
                    response_header = ProtocolHeader.decode(response_frame)
                    if response_header.opcode == OpCodes.OK and response_header.message_id == self.message_id_counter:
                        print("[CLIENT] Received PONG (ACK):", repr(response_header))
                    else:
                        print("[CLIENT] Received unexpected response:", repr(response_header))
                        print(repr(response_frame))

                time.sleep(10)  # Ping every 2 seconds

        except Exception as e:
            print("[CLIENT] Error in run loop:", e)
        finally:
            self.disconnect()

    def disconnect(self):
        self.is_connected = False
        if self.socket:
            self.socket.close()
        print("[CLIENT] Disconnected.")


# --- HOW TO RUN ---
# This script should be run from a command line with Jython, or within the Ignition Script Console.
# It will connect to the Ignition Gateway configured at the top.
if __name__ == "__main__":
    client = GANClient(GATEWAY_HOST, GATEWAY_PORT, USE_SSL)
    # Run the client in a separate thread so it doesn't block
    client_thread = threading.Thread(target=client.run)
    client_thread.daemon = True
    client_thread.start()

    # Keep the main script alive to see the output
    try:
        while client_thread.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping client...")
        client.disconnect()

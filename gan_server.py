# Corrected Script with WebSocket Handshake and Frame Parsing
# This can be run in the Ignition Gateway scope (e.g., Script Console)

from java.net import ServerSocket
from java.lang import Thread, Runnable
import threading
import hashlib
import base64
import struct
import io

# SSL Imports for the SSL version
from javax.net.ssl import SSLServerSocketFactory, KeyManagerFactory
from java.security import KeyStore, MessageDigest
from java.io import FileInputStream, InputStreamReader, BufferedReader, FileOutputStream
from java.util import Arrays
from jarray import array as jarray


# --- CONFIGURATION ---
# Port for the WebSocket Control Channel
WEBSOCKET_PORT = 8089
# Port for the HTTP Data Channel
HTTP_DATA_PORT = 8090
SERVER_ADDRESS = "127.0.0.1"

REMOTE_CONNECTION_ID = "my-python-sniffer"

DUMP_FILE_WS_PATH = "ws_capture.bin"
DUMP_FILE_HTTP_PATH = "http_capture.bin"
# Separator to write between frames for easier parsing later
FRAME_SEPARATOR = bytearray([0x00] * 8)

from metroparser import ProtocolHeader, OpCodes


def dump_frame(data_bytes, ws=True):
    """Appends the given bytes and a separator to the dump file."""
    try:
        f = DUMP_FILE_WS_PATH if ws else DUMP_FILE_HTTP_PATH
        # Use FileOutputStream with 'True' for append mode. This is thread-safe.
        fos = FileOutputStream(f, True)
        fos.write(jarray(data_bytes, 'b'))
        fos.write(FRAME_SEPARATOR)
        fos.close()
    except Exception as e:
        print("[DUMP] Error writing to file:", e)


# A simplified handler for a single client connection
class WebSocketControlHandler(Runnable):
    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.running = True

    def handle_handshake(self):
        """Reads the client's HTTP upgrade request and sends the WebSocket handshake response."""
        input_stream = self.client_socket.getInputStream()
        reader = BufferedReader(InputStreamReader(input_stream))

        headers = {}
        # Read HTTP request line
        request_line = reader.readLine()
        if not request_line:
            return False

        # Read headers until a blank line is found
        while True:
            line = reader.readLine()
            if not line:
                break
            parts = line.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()

        # Check for required WebSocket headers
        if 'sec-websocket-key' not in headers:
            print("Handshake failed: Missing Sec-WebSocket-Key header.")
            return False

        # --- Calculate the Sec-WebSocket-Accept response key ---
        # This is a mandatory part of the RFC 6455 protocol.
        key = headers['sec-websocket-key']
        magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sha1 = hashlib.sha1(key + magic_string).digest()
        accept_key = base64.b64encode(sha1)

        remote_system_id = "http://%s:%d/system" % (SERVER_ADDRESS, HTTP_DATA_PORT)

        # --- Send the 101 Switching Protocols response ---
        response = (
                       "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n"
                       "remoteSystemId: %s\r\n" # <-- What the client looks for
                       "\r\n"
                   ) % (accept_key, remote_system_id)

        self.client_socket.getOutputStream().write(response)
        self.client_socket.getOutputStream().flush()
        print("[WS-CTRL] WebSocket Handshake successful. Told client data channel is at:", remote_system_id)
        return True

    def read_websocket_frame(self):
        """Reads a single WebSocket frame and unmasks the payload."""
        input_stream = self.client_socket.getInputStream()

        # Read the first two bytes
        b1 = input_stream.read()
        b2 = input_stream.read()

        if b1 == -1 or b2 == -1:  # Connection closed
            return None

        opcode = b1 & 0x0F
        if opcode == 0x8:  # Opcode 8 is a CLOSE frame
            print("[WS-CTRL] Received WebSocket CLOSE frame from client.")
            return None

        # Determine payload length
        payload_len = b2 & 0x7F  # Unset the MASK bit
        if payload_len == 126:
            payload_len = (input_stream.read() << 8) | input_stream.read()
        elif payload_len == 127:
            payload_len = 0
            for i in range(8):
                payload_len = (payload_len << 8) | input_stream.read()

        # Read the 4-byte masking key
        masking_key = [input_stream.read() for _ in range(4)]

        # Read the masked payload
        masked_payload = [input_stream.read() for _ in range(payload_len)]

        # Unmask the payload using XOR
        unmasked_payload = [masked_payload[i] ^ masking_key[i % 4] for i in range(payload_len)]

        return "".join(map(chr, unmasked_payload))

    def _send_frame(self, payload_bytes, opcode):
        """Generic internal method to send a WebSocket frame."""
        payload_len = len(payload_bytes)

        # 0x80 (FIN bit) + opcode
        header = [0x80 | opcode]

        if payload_len <= 125:
            header.append(payload_len)
        elif payload_len <= 65535:
            header.append(126)
            header.append((payload_len >> 8) & 0xFF)
            header.append(payload_len & 0xFF)
        else:
            header.append(127)
            for i in range(8):
                header.append((payload_len >> (56 - 8 * i)) & 0xFF)

        signed_header_values = [b - 256 if b > 127 else b for b in header]
        java_header = jarray(signed_header_values, 'b')
        java_payload = jarray(payload_bytes, 'b')

        self.client_socket.getOutputStream().write(java_header)
        self.client_socket.getOutputStream().write(java_payload)
        self.client_socket.getOutputStream().flush()

    def send_text_frame(self, message_string):
        """Sends a WebSocket frame with the TEXT opcode (0x1)."""
        print("[WS-CTRL] Sending TEXT frame:", repr(message_string))
        self._send_frame(message_string.encode('utf-8'), 0x1)

    def send_binary_frame(self, message_bytes):
        """Sends a WebSocket frame with the BINARY opcode (0x2)."""
        print("[WS-CTRL] Sending BINARY frame of size:", len(message_bytes))
        self._send_frame(message_bytes, 0x2)

    def create_pong_response(self, original_message_id):
        """Constructs a PONG (ACK) frame in response to a PING."""
        # OpCode 1 is ACK (our PONG)
        # We must respond with the *same message ID* we received.
        # Format: Magic, Version, MsgID, OpCode, SubCode, Flags, SenderID, TargetAddr, SenderURL
        # We can send a minimal valid response.

        # We use struct.pack to create the binary data correctly.
        magic = struct.pack('>I', 0x00004941)
        version = struct.pack('>I', 1)
        msg_id = struct.pack('>H', original_message_id)
        opcode = struct.pack('>I', 1)  # OpCode 1 = ACK
        subcode = struct.pack('>I', 0)
        flags = struct.pack('>B', 0)

        # For simplicity, we can send empty strings for sender/target info in an ACK
        sender_id = struct.pack('>H', 0)
        target_addr = struct.pack('>H', 0)
        sender_url = struct.pack('>H', 0)

        return magic + version + msg_id + opcode + subcode + flags + sender_id + target_addr + sender_url

    def run(self):
        try:
            # Step 1: Perform the WebSocket (HTTP) handshake.
            if not self.handle_handshake():
                print("Failed Handshake !!")
                return

            # Step 2: Perform the Ignition GAN handshake by sending the remoteConnectionId.
            # This is what the Ignition client is waiting for after the HTTP handshake.
            self.send_text_frame("remoteConnectionId=%s" % REMOTE_CONNECTION_ID)
            print("Ignition (GAN) Handshake sent.")

            # Step 3: Now, listen for incoming frames from the Ignition client.
            print("Waiting for WebSocket frames from client...")
            while self.client_socket.isConnected() and not self.client_socket.isClosed():
                # Read the next properly framed and unmasked message
                raw_frame = self.read_websocket_frame()


                if raw_frame is None:
                    # Client closed the connection
                    break

                print("[WS-CTRL] Received Metro frame of size:", len(raw_frame))

                # header = self.parse_metro_header(raw_frame)
                header = ProtocolHeader.decode(raw_frame)

                if header.opcode == OpCodes.PING:
                    print("[WS-CTRL] Received PING:")

                    # Create a protocol-correct PONG response
                    response_header = ProtocolHeader()
                    response_header.message_id = header.message_id # CRITICAL: Use the same message ID
                    response_header.opcode = OpCodes.OK

                    response_header.sender_id = REMOTE_CONNECTION_ID
                    response_header.sender_url = "http://%s:%d/system" % (SERVER_ADDRESS, HTTP_DATA_PORT)
                    response_header.target_address = header.sender_id

                    # Encode the response and send it back
                    pong_message_bytes = response_header.encode()
                    self.send_binary_frame(pong_message_bytes)

                    # print(repr(pong_message_bytes))

                    # print("[WS-CTRL] Sent PONG (ACK):")
                elif header.opcode == OpCodes.SHUTDOWN:
                    print("[WS-CTRL] Received SHUTDOWN command:", repr(header))
                    print("[WS-CTRL] Acknowledging and closing connection.")
                    break

                elif header.opcode == OpCodes.MSG_SEND:
                    print("[WS-CTRL] Received MSG_SEND!:", repr(header))
                    print(repr(raw_frame))

                    dump_frame(raw_frame)

                    # Your sniffer logic for data packets would go here.
                    # For now, we still need to send an ACK to keep the connection alive.
                    response_header = ProtocolHeader()
                    response_header.message_id = header.message_id
                    response_header.opcode = OpCodes.OK
                    ack_bytes = response_header.encode()
                    self.send_binary_frame(ack_bytes)
                    print("[WS-CTRL] Sent ACK for MSG_SEND.")
                else:
                    print("[WS-CTRL] Received unknown OpCode:", repr(header))
                    print(repr(raw_frame))

                    dump_frame(raw_frame)
                # We can now implement the sniffer logic, e.g., dump the message
                # For now, we will just break after the first message for this example.
                # break

        # except Exception as e:
            # Handle cases where the client disconnects unexpectedly
            pass
        finally:
            self.client_socket.close()
            print("Client disconnected.")

    # def run(self):
    #     try:
    #         # In a real WebSocket implementation, you would perform the HTTP upgrade handshake here.
    #         # This is a complex process involving parsing HTTP headers and responding correctly.
    #         # For this example, we'll simulate the part after the handshake.
    #
    #         # The first message from the client would be the upgrade request.
    #         # After a successful handshake, you would get to this point.
    #
    #         # Simulate receiving the initial message from your JavaScript client
    #         # In a real scenario, you'd be reading from the socket's input stream
    #         client_address = self.client_socket.getRemoteSocketAddress()
    #         print("Client connected from:", client_address)
    #
    #         # Simulate the server sending its remoteConnectionId
    #         # This mimics: session.getRemote().sendStringByFuture(...)
    #         remote_id_message = "remoteConnectionId=my-python-sniffer\n"
    #         self.client_socket.getOutputStream().write(remote_id_message.encode('utf-8'))
    #         self.client_socket.getOutputStream().flush()
    #         print("Sent remoteConnectionId.")
    #
    #         # Now, you can listen for further messages
    #         input_stream = self.client_socket.getInputStream()
    #         while self.running:
    #             # This is a simplified read, a real implementation needs to handle
    #             # WebSocket framing (masking, opcode, payload length).
    #             # For basic text messages from your JS, this might show something.
    #             buffer = [0] * 1024
    #             bytes_read = input_stream.read(buffer)
    #
    #             if bytes_read == -1:
    #                 # The client has closed the connection
    #                 break
    #
    #             if bytes_read > 0:
    #                 message = "".join(map(chr, buffer[:bytes_read]))
    #                 print("Received from client:", message)
    #
    #                 # Echo the message back
    #                 echo_message = "Echo: Received data\n"
    #                 self.client_socket.getOutputStream().write(echo_message.encode('utf-8'))
    #                 self.client_socket.getOutputStream().flush()
    #
    #     except Exception as e:
    #         print("Error in client handler:", e)
    #     finally:
    #         self.client_socket.close()
    #         print("Client disconnected.")


class HttpDataHandler(Runnable):
    def __init__(self, client_socket):
        self.client_socket = client_socket

    def run(self):
        try:
            input_stream = self.client_socket.getInputStream()
            reader = BufferedReader(InputStreamReader(input_stream))

            # Read request line and headers to find content length
            content_length = 0
            while True:
                line = reader.readLine()
                if line is None or line.isEmpty(): break
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":")[1].strip())

            # Read the POST body (the data packet)
            body = [0] * content_length
            for i in range(content_length):
                body[i] = reader.read()

            dump_frame(body, ws=False)

            print("[HTTP-DATA] Received POST data packet of size:", content_length, "bytes.")
            # Here you would add your logic to parse/dump the 'body' byte array.

            # Send a simple 200 OK response to satisfy the client
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            self.client_socket.getOutputStream().write(response.encode('utf-8'))
            self.client_socket.getOutputStream().flush()

        except Exception as e:
            print("[HTTP-DATA] Error:", e)
        finally:
            self.client_socket.close()
            print("[HTTP-DATA] Client disconnected.")

# --- Main Server Logic ---
class WebSocketControlServer(Runnable):
    def __init__(self, port):
        self.port = port
        self.server_socket = ServerSocket(self.port)
        self.running = True
        print("Server started on port:", self.port)

    def run(self):
        while self.running:
            try:
                client_socket = self.server_socket.accept()
                handler = WebSocketControlHandler(client_socket)
                thread = Thread(handler)
                thread.start()
            except Exception as e:
                print("Server error:", e)
                self.running = False

class HttpDataServer(Runnable):
    def __init__(self, port):
        self.port = port
        self.server_socket = ServerSocket(self.port)
        print( "[HTTP-DATA] Server listening on port:", self.port)
    def run(self):
        while True:
            try:
                client_socket = self.server_socket.accept()
                handler = HttpDataHandler(client_socket)
                Thread(handler).start()
            except Exception as e: break

# You would then connect your JavaScript to ws://127.0.0.1:8088
# The path and query parameters are part of the HTTP upgrade request and would need
# to be handled in a more complete implementation.```

### Handling SSL

"""
To make this work with SSL, you'll need to use `javax.net.ssl.SSLServerSocketFactory` to create an `SSLServerSocket`. This requires a KeyStore containing the server's certificate.

Ignition's GAN uses a keystore located at `<Ignition-Install-Dir>/webserver/metro-keystore`. You would need to load this keystore in your Python/Jython code. The default password is "metro".

Here's a conceptual modification for SSL:
"""


# --- Modified WebSocketServer for SSL ---
class SSLWebSocketServer(Runnable):
    def __init__(self, port, keystore_path, keystore_pass):
        self.port = port
        
        # Load the keystore
        ks = KeyStore.getInstance("JKS")
        ks.load(FileInputStream(keystore_path), list(keystore_pass))

        # Set up the KeyManagerFactory
        kmf = KeyManagerFactory.getInstance("SunX509")
        kmf.init(ks, list(keystore_pass))

        # Get the SSLServerSocketFactory and create the SSLServerSocket
        context = javax.net.ssl.SSLContext.getInstance("TLS")
        context.init(kmf.getKeyManagers(), None, None)
        ssf = context.getServerSocketFactory()

        # Get the SSLServerSocketFactory
        # ssf = SSLServerSocketFactory.getDefault()
        self.server_socket = ssf.createServerSocket(self.port)
        
        self.running = True
        print("SSL Server started on port:", self.port)

    def run(self):
        # ... the rest of the run method is the same as the non-SSL version
        while self.running:
            try:
                client_socket = self.server_socket.accept()

                # Create and start a new thread to handle this client
                handler = WebSocketControlHandler(client_socket)
                thread = Thread(handler)
                thread.start()
            except Exception as e:
                print("Server error:", e)
                self.running = False



# Note: To stop the server, you'd need to add a mechanism to set server.running = False
# For this example, you'll have to restart the Gateway or script console to stop it.

ws_server = WebSocketControlServer(WEBSOCKET_PORT)
ws_thread = threading.Thread(target=ws_server.run)
# ws_server.daemon = True # Allows the script to exit without waiting for the thread
ws_thread.start()

http_server = HttpDataServer(HTTP_DATA_PORT)
http_thread = threading.Thread(target=http_server.run)
# http_thread.daemon = True
http_thread.start()

print("Servers started. Ensure Ignition outgoing connection is pointed to port %d and saved." % WEBSOCKET_PORT)

# To run this:
# keystore_path = "path/to/your/metro-keystore"
# keystore_pass = "metro"
# ssl_server = SSLWebSocketServer(8060, keystore_path, keystore_pass) # Use port 8060 for SSL
# ... start in a thread as before
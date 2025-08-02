# File: gan_server.py

import socket
import ssl
import threading
import hashlib
import base64
import struct
import os
from typing import Dict
from urllib.parse import urlparse, parse_qs

# --- CONFIGURATION ---
# Port for the WebSocket Control Channel
WEBSOCKET_PORT = 5060
# Port for the HTTP Data Channel
HTTP_DATA_PORT = 5088
SERVER_ADDRESS = "127.0.0.1"

REMOTE_CONNECTION_ID = "my-python-sniffer"

DUMP_FILE_WS_PATH = "ws_capture.bin"
DUMP_FILE_HTTP_PATH = "http_capture.bin"
# Separator to write between frames for easier parsing later
FRAME_SEPARATOR = bytearray([0x00] * 8)

from metroparser import ProtocolHeader, OpCodes

active_connections: Dict[str, 'WebSocketControlHandler'] = {} # Maps remote_system_name -> WebSocketControlHandler instance
connections_lock = threading.Lock() # Lock for thread-safe access to active_connections

def dump_frame(data_bytes, ws=True):
    """Appends the given bytes and a separator to the dump file."""
    try:
        f = DUMP_FILE_WS_PATH if ws else DUMP_FILE_HTTP_PATH
        with open(f, 'ab') as file:  # 'ab' for append binary
            file.write(bytes(data_bytes))
            file.write(FRAME_SEPARATOR)
    except Exception as e:
        print(f"[DUMP] Error writing to file: {e}")


def generate_ssl_files():
    """Generate self-signed SSL certificate and key for testing."""
    print("Generating SSL certificate and key...")
    
    # Commands to generate SSL files using OpenSSL
    commands = [
        "openssl genrsa -out server.key 2048",
        "openssl req -new -key server.key -out server.csr -subj '/CN=localhost'",
        "openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt",
        "cat server.key server.crt > server.pem"
    ]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        os.system(cmd)
    
    print("SSL files generated: server.key, server.crt, server.csr, server.pem")


# A simplified handler for a single client connection
class WebSocketControlHandler:
    def __init__(self, client_socket, remote_system_name: str | None=None):
        self.client_socket = client_socket
        self.remote_system_name = remote_system_name
        self.running = True

        if self.remote_system_name:
            with connections_lock:
                active_connections[self.remote_system_name] = self
            print(f"[WS-CTRL] Registered connection: {self.remote_system_name}")

    def on_data_received(self, header, raw_message_body):
        """
        Handles an incoming data message sent via the HTTP data channel.
        This is the Python equivalent of the Java WebSocketConnection.onDataReceived.
        """
        try:
            print(f"[WS-CTRL] [{self.remote_system_name}] onDataReceived: {repr(header)}")
            # 1. Check for ACCESS_DENIED (placeholder)
            access_denied = False # Placeholder

            if access_denied:
                # Send ACCESS_DENIED response
                response_header = ProtocolHeader()
                response_header.message_id = header.message_id
                response_header.opcode = OpCodes.ACCESS_DENIED # Make sure this exists in OpCodes
                response_header.sender_id = REMOTE_CONNECTION_ID # Or appropriate ID
                response_header.sender_url = f"http://{SERVER_ADDRESS}:{HTTP_DATA_PORT}/system"
                self.send_binary_frame(response_header.encode())
                print(f"[WS-CTRL] [{self.remote_system_name}] Sent ACCESS_DENIED for message {header.message_id}")
                return # Stop processing

            # 2. Handle specific opcodes
            if header.opcode == OpCodes.ERROR: # 4
                # self.handle_remote_error(header) #TODO: implement this
                return

            # 3. Process MSG_SEND (OpCode 3) - Download/Forward logic
            if header.opcode == OpCodes.MSG_SEND: # 3
                print(f"[WS-CTRL] [{self.remote_system_name}] Received MSG_SEND via data channel. Scheduling download/processing.")
                # In Java, this triggers RunDownload which does an HTTP GET.
                # In this simplified Python proxy, we might just acknowledge or process the body directly if available.
                # For now, let's just acknowledge it was received via data channel.
                # You might need to implement the actual message forwarding/downloading logic here.
                # Placeholder: Just send ACK
                response_header = ProtocolHeader()
                response_header.message_id = header.message_id
                response_header.opcode = OpCodes.OK # 1
                response_header.sender_id = REMOTE_CONNECTION_ID
                response_header.sender_url = f"http://{SERVER_ADDRESS}:{HTTP_DATA_PORT}/system"
                self.send_binary_frame(response_header.encode())
                print(f"[WS-CTRL] [{self.remote_system_name}] Sent ACK for MSG_SEND (data channel).")
                dump_frame(raw_message_body, ws=False) # Dump the body received via HTTP POST

            # 4. Handle other opcodes if necessary (PING handled in WS control loop)

            # 5. Default ACK for other cases (simplified)
            # (Java sends ACK/ERROR based on processing result)
            # else:
            #     response_header = ProtocolHeader()
            #     response_header.message_id = header.message_id
            #     response_header.opcode = OpCodes.OK
            #     self.send_binary_frame(response_header.encode())

        except Exception as e:
            print(f"[WS-CTRL] [{self.remote_system_name}] Error in onDataReceived: {e}")
            # Potentially send an ERROR response back via WebSocket?
            # ... error handling ...

    def handle_handshake(self):
        """Reads the client's HTTP upgrade request and sends the WebSocket handshake response."""
        try:
           # Read HTTP request
            request_data = self.client_socket.recv(4096*8) # Increased buffer size
            if not request_data:
                print("[WS-CTRL] No data received during handshake.")
                return False

            # --- Distinguish between GET and POST ---
            request_line_end = request_data.find(b'\r\n')
            if request_line_end == -1:
                print("[WS-CTRL] Malformed request: No request line found.")
                return False

            request_line = request_data[:request_line_end].decode('utf-8')
            print(f"[WS-CTRL] Request Line: {request_line}")
            parts = request_line.split(' ')
            if len(parts) < 2:
                print("[WS-CTRL] Malformed request line.")
                return False

            method = parts[0]
            path_and_query = parts[1]

            if method not in ["POST", "GET"]:
                print("[WS-CTRL] Invalid method %s." % method)
                return False

            headers_end = request_data.find(b'\r\n\r\n')
            if headers_end == -1:
                print("[WS-CTRL] Malformed HTTP request: No header/body separator found.")
                return False
        
            headers_part = request_data[:headers_end].decode('utf-8')
            content_length = 0
            headers_dict = {}
            for line in headers_part.split('\r\n')[1:]: # Skip request line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers_dict[key.strip().lower()] = value.strip()
                    if key.strip().lower() == 'content-length':
                        content_length = int(value.strip())


            # --- Handle POST to /system/ws-datachannel-servlet ---
            if method == "POST" and path_and_query.startswith("/system/ws-datachannel-servlet"):
                print("[WS-CTRL] Handling POST to data channel servlet.")
                # Extract body
                body_start = headers_end + 4
                raw_body = request_data[body_start:]

                if content_length == 0 and raw_body[:4] != b'\x00\x00IA':
                    size_end = raw_body.find(b'\r\n')
                    if size_end > 0 and size_end < 8:  # TODO: 8 is guesstimated. Maybe more ? It's plain text hex of the length
                        content_length = int(raw_body[:size_end], 16)
                        
                        ia_obj = request_data[body_start+size_end+2:body_start+size_end+2+content_length ]
                        extra_obj = request_data[body_start+size_end+2+content_length:]
                        # extra_obj = b'\r\n0\r\n\r\n' ?
                    else:
                        print(f"[WS-CTRL] Incomplete POST data received. Invalid header size at {size_end} (should be between 1 and 8).")
                        ia_obj = raw_body
                else:
                    print(f"[WS-CTRL] Somehow, a valid POST data was passed. Should not happen, but here we are...")
                    ia_obj = raw_body

                if len(ia_obj) < content_length:
                    print(f"[WS-CTRL] Incomplete POST data received. Expected {content_length} bytes.")
                    # Ideally, you'd loop to receive the full body if needed.
                    # For simplicity, assuming it's all here or handling failure.
                    # Let's try to decode what we have for debugging.

                print(f"[WS-CTRL] Received POST body of size: {len(ia_obj)} bytes.")

                with open("POST_data{}.bin".format(time.time()), 'ab') as file:  # 'ab' for append binary
                    file.write(raw_body)
                
                # --- Decode ProtocolHeader ---
                try:
                    header = ProtocolHeader.decode(ia_obj)
                    print(f"[WS-CTRL] Decoded header from POST: {repr(header)}")
                except Exception as decode_error:
                    print(f"[WS-CTRL] Failed to decode ProtocolHeader from POST body: {decode_error}")
                    print(f"[WS-CTRL] Raw body snippet: {ia_obj[:100]}")
                    return False # Cannot proceed without header

                # --- Find associated WebSocket connection ---
                sender_id = header.sender_id
                if not sender_id:
                    print("[WS-CTRL] POST header missing sender_id.")
                    return False

                target_handler = None
                with connections_lock:
                    target_handler = active_connections.get(sender_id)

                if not target_handler:
                    print(f"[WS-CTRL] No active connection found for sender_id: '{sender_id}' from POST.")
                    # Send HTTP error response?
                    error_response = (
                        "HTTP/1.1 404 Not Found\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    )
                    self.client_socket.send(error_response.encode('utf-8'))
                    return False # Indicate handshake (for this POST path) failed
                
                # --- Dispatch to the connection's handler ---
                # Pass the header and the raw body (minus the header part) for processing
                # Calculate header size (approximation or use struct.calcsize if fixed part known)
                # For simplicity, re-decode the header to get its size or assume the rest is the body
                # A more robust way is to calculate the header size during decoding in ProtocolHeader
                # Let's assume raw_body starts with the full header for now.
                # I might need to adjust this based on how ProtocolHeader.decode consumes the stream.
                # If ProtocolHeader.decode consumes the stream, I need to pass the stream or remaining data.
                # Simplification: Pass the whole body for now, let on_data_received handle parsing if needed
                # Or pass header and body separately if body follows header in the stream.

                # Let's assume the raw_body IS the complete message including header for this path.
                # The target_handler.on_data_received should be able to handle it.
                # Pass the header we already decoded and the raw body
                target_handler.on_data_received(header, ia_obj) # TODO: should I pass the raw_body ? or the obj ?

                # Send simple HTTP 200 OK response to the POST
                ok_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                self.client_socket.send(ok_response.encode('utf-8'))
                print(f"[WS-CTRL] Dispatched POST data to connection '{sender_id}' and sent HTTP 200 OK.")
                # This path doesn't upgrade to WS, it just handles the POST and closes.
                return False # Signal that standard WS run loop should NOT start
                
            elif method == "GET" and path_and_query.startswith("/system/ws-control-servlet"):
                print("[WS-CTRL] Handling GET WebSocket upgrade.")
                # Decode the full request as UTF-8 for header parsing
                

                # --- Extract connection identifier (name or uuid) from query parameters ---
                parsed_url = urlparse(path_and_query)
                query_params = parse_qs(parsed_url.query)
                # Use 'uuid' if available, otherwise 'name'
                remote_system_name = None
                if 'name' in query_params and query_params['name']:
                    remote_system_name = query_params['name'][0]
                elif 'uuid' in query_params and query_params['uuid']:
                    remote_system_name = query_params['uuid'][0]
                
                if not remote_system_name:
                    print("[WS-CTRL] Handshake failed: Missing 'uuid' or 'name' in query parameters.")
                    return False

                self.remote_system_name = remote_system_name # Store identifier

                # Check for required WebSocket headers
                if 'sec-websocket-key' not in headers_dict:
                    print("Handshake failed: Missing Sec-WebSocket-Key header.")
                    return False

                # --- Calculate the Sec-WebSocket-Accept response key ---
                key = headers_dict['sec-websocket-key']
                magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                accept_key = key + magic_string
                sha1_hash = hashlib.sha1(accept_key.encode('utf-8')).digest()
                accept_response = base64.b64encode(sha1_hash).decode('utf-8')
                remote_system_id = f"http://{SERVER_ADDRESS}:{HTTP_DATA_PORT}/system"

                # --- Send the 101 Switching Protocols response ---
                response = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept_response}\r\n"
                    f"remoteSystemId: {remote_system_id}\r\n"
                    "\r\n"
                )
                self.client_socket.send(response.encode('utf-8'))
                print(f"[WS-CTRL] WebSocket Handshake successful for '{self.remote_system_name}'. Data channel: {remote_system_id}")

                # --- Register the connection AFTER successful handshake ---
                with connections_lock:
                    active_connections[self.remote_system_name] = self
                print(f"[WS-CTRL] Registered connection: {self.remote_system_name}")

                return True # Signal successful WS handshake
            else:
                print(f"[WS-CTRL] Unsupported method ({method}) or path ({path_and_query}).")
                # Send 404 or 405?
                not_found_response = (
                    "HTTP/1.1 404 Not Found\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                self.client_socket.send(not_found_response.encode('utf-8'))
                return False
        except Exception as e:
            print(f"Handshake error: {e}")
            try:
                error_response = (
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                self.client_socket.send(error_response.encode('utf-8'))
            except:
                pass # Ignore errors sending error response
            return False

    def read_websocket_frame(self):
        """Reads a single WebSocket frame and unmasks the payload."""
        try:
            # Read the first two bytes
            header_bytes = self._recv_all(2)
            if not header_bytes or len(header_bytes) < 2:
                return None

            b1, b2 = header_bytes[0], header_bytes[1]
            opcode = b1 & 0x0F
            
            if opcode == 0x8:  # Opcode 8 is a CLOSE frame
                print("[WS-CTRL] Received WebSocket CLOSE frame from client.")
                return None

            # Determine payload length
            payload_len = b2 & 0x7F  # Unset the MASK bit
            if payload_len == 126:
                extended_payload_len = self._recv_all(2)
                payload_len = struct.unpack("!H", extended_payload_len)[0]
            elif payload_len == 127:
                extended_payload_len = self._recv_all(8)
                payload_len = struct.unpack("!Q", extended_payload_len)[0]

            # Read the 4-byte masking key (client-to-server frames are always masked)
            masking_key = self._recv_all(4)

            # Read the masked payload
            masked_payload = self._recv_all(payload_len)

            # Unmask the payload using XOR
            unmasked_payload = bytearray()
            for i in range(payload_len):
                unmasked_payload.append(masked_payload[i] ^ masking_key[i % 4])

            return bytes(unmasked_payload)
        except Exception as e:
            print(f"[WS-CTRL] Error reading WebSocket frame: {e}")
            return None

    def _recv_all(self, length):
        """Helper method to receive exactly 'length' bytes."""
        data = b""
        while len(data) < length:
            chunk = self.client_socket.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _send_frame(self, payload_bytes, opcode):
        """Generic internal method to send a WebSocket frame."""
        payload_len = len(payload_bytes)

        # 0x80 (FIN bit) + opcode
        header = bytearray()

        # FIN bit + opcode
        header.append(0x80 | opcode)

        # Payload length
        if payload_len <= 125:
            header.append(payload_len)
        elif payload_len <= 65535:
            header.append(126)
            header.extend(struct.pack("!H", payload_len))
        else:
            header.append(127)
            header.extend(struct.pack("!Q", payload_len))

        # Send the frame
        try:
            self.client_socket.send(header + payload_bytes)
        except Exception as e:
            print(f"[WS-CTRL] Error sending WebSocket frame: {e}")

    def send_text_frame(self, message_string):
        """Sends a WebSocket frame with the TEXT opcode (0x1)."""
        print(f"[WS-CTRL] Sending TEXT frame: {repr(message_string)}")
        self._send_frame(message_string.encode('utf-8'), 0x1)

    def send_binary_frame(self, message_bytes):
        """Sends a WebSocket frame with the BINARY opcode (0x2)."""
        print(f"[WS-CTRL] Sending BINARY frame of size: {len(message_bytes)}")
        self._send_frame(message_bytes, 0x2)

    def create_pong_response(self, original_message_id):
        """Constructs a PONG (ACK) frame in response to a PING."""
        # Simplified PONG response
        response_header = ProtocolHeader()
        response_header.message_id = original_message_id
        response_header.opcode = OpCodes.OK
        response_header.sender_id = REMOTE_CONNECTION_ID
        response_header.sender_url = f"http://{SERVER_ADDRESS}:{HTTP_DATA_PORT}/system"
        return response_header.encode()

    def run(self):
        try:
            # Step 1: Perform the WebSocket (HTTP) handshake.
            if not self.handle_handshake():
                print("[WS-CTRL] Handshake process completed (not necessarily failed).")
                # If handle_handshake returned False for POST, the connection should close.
                # If it returned False for failed WS handshake, also close.
                return # Exit the run loop

            # Step 2: Perform the Ignition GAN handshake by sending the remoteConnectionId.
            self.send_text_frame(f"remoteConnectionId={REMOTE_CONNECTION_ID}")
            print("[WS-CTRL] Ignition (GAN) Handshake sent.")

            # Step 3: Now, listen for incoming frames from the Ignition client.
            print("[WS-CTRL] Waiting for WebSocket frames from client...")
            while self.running:
                # Read the next properly framed and unmasked message
                raw_frame = self.read_websocket_frame()

                if raw_frame is None:
                    print("[WS-CTRL] Client closed connection or error reading frame.")
                    break # TODO: Exit loop with break ?

                print(f"[WS-CTRL] [{self.remote_system_name}] Received Metro frame of size: {len(raw_frame)}")
                try:
                    header = ProtocolHeader.decode(raw_frame)
                except Exception as decode_err:
                    print(f"[WS-CTRL] [{self.remote_system_name}] Error decoding frame header: {decode_err}")
                    print(f"[WS-CTRL] [{self.remote_system_name}] Raw frame snippet: {raw_frame[:50]}")
                    # Decide whether to close connection or continue
                    continue

                if header.opcode == OpCodes.PING:
                    print(f"[WS-CTRL] [{self.remote_system_name}] Received PING")
                    pong_message_bytes = self.create_pong_response(header.message_id)
                    self.send_binary_frame(pong_message_bytes)
                    print(f"[WS-CTRL] [{self.remote_system_name}] Sent PONG (ACK)")

                elif header.opcode == OpCodes.SHUTDOWN:
                    print(f"[WS-CTRL] [{self.remote_system_name}] Received SHUTDOWN command: {repr(header)}")
                    print("[WS-CTRL] Acknowledging and closing connection.")
                    # Send ACK before closing?
                    ack_header = ProtocolHeader()
                    ack_header.message_id = header.message_id
                    ack_header.opcode = OpCodes.OK
                    self.send_binary_frame(ack_header.encode())
                    break # Exit loop

                elif header.opcode == OpCodes.MSG_SEND:
                    print(f"[WS-CTRL] [{self.remote_system_name}] Received MSG_SEND (WS): {repr(header)}")
                    # print(repr(raw_frame)) # Optional debug
                    dump_frame(raw_frame)
                    # Send ACK to keep the connection alive
                    response_header = ProtocolHeader()
                    response_header.message_id = header.message_id
                    response_header.opcode = OpCodes.OK
                    ack_bytes = response_header.encode()
                    self.send_binary_frame(ack_bytes)
                    print(f"[WS-CTRL] [{self.remote_system_name}] Sent ACK for MSG_SEND (WS).")
                else:
                    print(f"[WS-CTRL] [{self.remote_system_name}] Received unknown OpCode: {OpCodes.get_name(header.opcode)} ({header.opcode}) : {repr(header)}")
                    print(repr(raw_frame))
                    dump_frame(raw_frame)

        except Exception as e:
            if self.running: # Only print if not intentionally stopping
                print(f"[WS-CTRL] [{getattr(self, 'remote_system_name', 'Unknown')}] Error in client handler run loop: {e}")
                import traceback
                traceback.print_exc()
        finally:
            self.running = False # Ensure flag is set
            # --- Unregister the connection ---
            if hasattr(self, 'remote_system_name') and self.remote_system_name:
                with connections_lock:
                    if self.remote_system_name in active_connections:
                        del active_connections[self.remote_system_name]
                print(f"[WS-CTRL] Unregistered connection: {self.remote_system_name}")

            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
            print("[WS-CTRL] Client disconnected and resources cleaned up.")

class HttpDataHandler:
    def __init__(self, client_socket):
        self.client_socket = client_socket

    def run(self):
        try:
            # Read HTTP request
            request_data = self.client_socket.recv(4096)
            
            # Parse headers to find content length
            headers_end = request_data.find(b'\r\n\r\n')
            if headers_end != -1:
                headers_part = request_data[:headers_end].decode('utf-8')
                content_length = 0
                
                for line in headers_part.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':')[1].strip())
                
                # Extract body if present
                body_start = headers_end + 4
                if len(request_data) > body_start:
                    body = request_data[body_start:body_start + content_length]
                    dump_frame(body, ws=False)
                    print(f"[HTTP-DATA] Received POST data packet of size: {len(body)} bytes.")

            # Send a simple 200 OK response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            self.client_socket.send(response.encode('utf-8'))

        except Exception as e:
            print(f"[HTTP-DATA] Error: {e}")
        finally:
            self.client_socket.close()
            print("[HTTP-DATA] Client disconnected.")


# --- Main Server Logic ---
class WebSocketControlServer:
    def __init__(self, port, use_ssl=False, certfile="server.crt", keyfile="server.key"):
        self.port = port
        self.use_ssl = use_ssl
        self.certfile = certfile
        self.keyfile = keyfile
        self.server_socket = None
        self.running = True
        
        if use_ssl:
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            
            # Create regular socket and wrap with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket = context.wrap_socket(sock, server_side=True)
        else:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        print(f"Server started on port: {self.port}")

    def run(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"Client connected from: {address}")
                handler = WebSocketControlHandler(client_socket)
                thread = threading.Thread(target=handler.run)
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")
                break

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class HttpDataServer:
    def __init__(self, port):
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)
        print(f"[HTTP-DATA] Server listening on port: {self.port}")

    def run(self):
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[HTTP-DATA] Client connected from: {address}")
                handler = HttpDataHandler(client_socket)
                thread = threading.Thread(target=handler.run)
                thread.daemon = True
                thread.start()
            except Exception as e:
                print(f"[HTTP-DATA] Server error: {e}")
                break

    def stop(self):
        if self.server_socket:
            self.server_socket.close()


# --- HOW TO RUN ---
if __name__ == "__main__":
    print("GAN Server - Python 3 WebSocket Server")
    print("=" * 50)
    
    # Check if SSL files exist, if not generate them
    if not os.path.exists("server.pem"):
        print("SSL certificate not found. Generating...")
        generate_ssl_files()
    
    # Create and start servers
    ws_server = WebSocketControlServer(WEBSOCKET_PORT, use_ssl=True)
    http_server = HttpDataServer(HTTP_DATA_PORT)
    
    # Start server threads
    ws_thread = threading.Thread(target=ws_server.run)
    ws_thread.daemon = True
    ws_thread.start()
    
    http_thread = threading.Thread(target=http_server.run)
    http_thread.daemon = True
    http_thread.start()
    
    print(f"Servers started. WebSocket on port {WEBSOCKET_PORT}, HTTP Data on port {HTTP_DATA_PORT}")
    print("Press Ctrl+C to stop servers")
    
    try:
        # Keep main thread alive
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...")
        ws_server.stop()
        http_server.stop()
        print("Servers stopped.")

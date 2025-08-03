# File: gan_client.py

import io
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
GATEWAY_PORT = 8088  # Use 8088 for default non-SSL
DATA_CHANNEL_PORT = 8060 
USE_SSL = False  # Change to True to connect to a default SSL-enabled Gateway
DATA_USE_SSL = True

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

    def send(self, msg):
        print("WS-SEND", msg)
        return self.socket.send(msg)

    def recv(self, size):
        msg = self.socket.recv(size)
        print("WS-RECV", msg)
        return msg

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
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Also allow port reuse if the OS supports it
                try:
                    self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass

                # Wrap with SSL
                self.socket = context.wrap_socket(self._sock, server_hostname=self.host)
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock = self.socket
            
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
            "Accept-Encoding: gzip\r\n"
            "User-Agent: Jetty/9.4.24.v20191120\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Pragma: no-cache\r\n"
            "Cache-Control: no-cache\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "\r\n"
        )

        print("[CLIENT] Sending WebSocket handshake request...")
        self.send(request.encode('utf-8'))

        # 3. Read and validate the server's response
        response = self.recv(1024).decode('utf-8')
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
            chunk = self.recv(length - len(data))
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
            self.send(header + masked_payload)
        except Exception as e:
            print(f"[CLIENT] Error sending WebSocket frame: {e}")

    def http_req(
        self,
        host: str,
        port: int,
        payload: bytes,
        use_ssl: bool = False,
        timeout: float = 5.0,
        verify_cert: bool = False,
        cafile: None = None,
        certfile: str ="server.crt",
        keyfile: str ="server.key",
    ) -> bytes:
        """
        Connects to host:port, optionally wraps in SSL, sends payload, and returns full response.
        If verify_cert is False, certificate validation is disabled.
        """
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if use_ssl:
                if verify_cert:
                    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    if cafile:
                        context.load_verify_locations(cafile)
                else:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                if certfile:
                    # client cert if needed
                    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
                ssock = context.wrap_socket(sock, server_hostname=host)
            else:
                ssock = sock

            ssock.settimeout(timeout)
            ssock.sendall(payload)

            # Read until remote closes or timeout
            response = bytearray()
            try:
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            except socket.timeout:
                # expected when no more data arrives
                pass
            except Exception:
                pass

            return bytes(response)


    def get_datachannel(self, msg_id, connectionId):
        """Performs the GET to the data channel servlet with given id and connectionId."""
        path = f"/system/ws-datachannel-servlet?id={msg_id}&connectionId={connectionId}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: Keep-Alive\r\n"
            "User-Agent: Apache-HttpClient/4.5.11 (Java/11.0.11)\r\n" #  Ignition-GAN-Client/1.0\r\n" ?
            "Accept-Encoding: gzip,deflate\r\n"
            "\r\n"
        )

        try:
            print(f"[CLIENT-DATA] Sending GET {path}")
            raw = self.http_req(self.host, DATA_CHANNEL_PORT, request.encode("utf-8"), use_ssl=DATA_USE_SSL)
            # with socket.create_connection((self.host, DATA_CHANNEL_PORT), timeout=5) as sock:
            #     if DATA_USE_SSL:
            #         # Create insecure context (skip cert verification)
            #         ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            #         ctx.check_hostname = False
            #         ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
            #         ctx.verify_mode = ssl.CERT_NONE
            
            #         sock = ctx.wrap_socket(sock, server_hostname=self.host)
                    
            #     sock.sendall(request.encode("utf-8"))

            #     time.sleep(2)

            #     # Read full response
            #     try:
            #         raw = b""
            #         while True:
            #             chunk = sock.recv(4096)
            #             if not chunk:
            #                 break
            #             raw += chunk
            #     except Exception as e:
            #         pass

            print(raw)
            with open("CLIENT/CLIENT_GET_data{}.bin".format(time.time()), 'ab') as file:  # 'ab' for append binary
                    file.write(raw)

            # Split headers / body
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                print("[CLIENT-DATA] Malformed HTTP response, no header/body separator.")
                stream = io.BytesIO(bytes(raw))
                headers_size,  = struct.unpack(">B", stream.read(1))
                header_length, = struct.unpack(">B", stream.read(1))
                headers = stream.read(headers_size-1)
                body = stream.read()
            else:
                sizes = raw[:sep].decode("utf-8", errors="ignore")
                headers = raw[sep + 4 :]
            
            print(f"[CLIENT-DATA] Response headers:\n{headers.splitlines()[0]}")
            # Now interpret the body as Metro frame: protocol header + payload
            try:
                header = ProtocolHeader.decode(headers)
                print(f"[CLIENT-DATA] Datachannel reply header: {repr(header)}")
                # Further processing of body after header would go here
                return header, body
            except Exception as e:
                print(f"[CLIENT-DATA] Failed to decode ProtocolHeader from GET response: {e}")
                return None
        except Exception as e:
            print(f"[CLIENT-DATA] get_datachannel error: {e}")
            return None

    def post_to_datachannel(self, data_file_path, message_id):
        """Connects via HTTP, crafts headers, and POSTs the file content."""
        try:
            with open(data_file_path, "rb") as f:
                post_data = f.read()

            protocol = ProtocolHeader()
            protocol.message_id = message_id  # new ID ?
            protocol.opcode = OpCodes.MSG_SEND
            protocol.subcode = 0
            protocol.flags = 0
            protocol.sender_id = CLIENT_NAME
            # protocol.target_address = "_0:0:Ignition-Forge-DEV"
            protocol.sender_url = CLIENT_URL  # optional, can be left blank

            post_data = protocol.encode() + post_data
            content_length = len(post_data)
            
            # Use chunked transfer encoding as observed
            hex_content_length = f"{content_length:x}\r\n".encode('utf-8')

            # Craft the HTTP POST request
            request_body = hex_content_length + post_data + b"\r\n0\r\n\r\n"
            
            # NOTE: The port here should be the one the server's DATA channel is listening on.
            # This is provided in the `remoteSystemId` header during the WS handshake.
            # For simplicity, we hardcode it here based on the sniffer server's config.
            
            request_headers = (
                f"POST /system/ws-datachannel-servlet HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n"
                f"Host: {self.host}:{DATA_CHANNEL_PORT}\r\n"
                "Connection: Keep-Alive\r\n"
                "User-Agent: Apache-HttpClient/4.5.11 (Java/11.0.11)\r\n"
                # "User-Agent: Ignition-GAN-Client/1.0\r\n"
                "Accept-Encoding: gzip,deflate\r\n"
                # "Content-Type: application/octet-stream\r\n"
                "\r\n"
            )

            payload = request_headers.encode('utf-8') + request_body
            response = self.http_req(self.host, DATA_CHANNEL_PORT, payload, use_ssl=DATA_USE_SSL)

            # print(f"[CLIENT-DATA] Connecting to HTTP data channel on port {DATA_CHANNEL_PORT}...")
            # http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # http_socket.connect((self.host, DATA_CHANNEL_PORT))
            
            # print(f"[CLIENT-DATA] Sending POST request with {content_length} bytes of data.")
            # http_socket.sendall(request_headers.encode('utf-8'))
            # http_socket.sendall(request_body)

            # response = http_socket.recv(4096)
            print("HTTP-RECV", response)
            print(f"[CLIENT-DATA] Received response: {response.decode('utf-8').splitlines()[0]}")
            # http_socket.close()

        except Exception as e:
            print(f"[CLIENT-DATA] Failed to post to data channel: {e}")

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

            # Phase 3: Main PING loop and data POST
            ping_count = 0
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
                    if response_header.opcode == OpCodes.OK: # and response_header.message_id == self.message_id_counter:
                        print(f"[CLIENT] Received PONG (ACK): {repr(response_header)}")
                    elif response_header.opcode == OpCodes.MSG_SEND:
                        print(f"[CLIENT] Received MSG_SEND: {repr(response_header)}")
                        print(response_frame)
                        # TODO: GET response_header.sender_url + "ws-datachannel-servlet" + "?id={response_header.message_id}&connectionId={CLIENT_NAME}"
                        self.get_datachannel(response_header.message_id, connectionId=CLIENT_NAME)

                        self.post_to_datachannel("POST_datachannel.bin", response_header.message_id)
                    else:
                        print(f"[CLIENT] Received unexpected response: {repr(response_header)}")
                        print(repr(response_frame))


                ping_count += 1

                # Check if it's time to POST data
                # if ping_count == 2:
                #     print("[CLIENT] Two PINGs sent, preparing to POST data...")
                #     self.post_to_datachannel("POST_datachannel.bin")
                #     # For this example, we will disconnect after posting.
                #     # break

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
                self.send(close_frame)
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
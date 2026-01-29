import ssl
import time
import socket
import selectors
from enum import Enum

from cache import Cache
from load_balancer import LoadBalancer
from utilities import parse_request, reconstruct_request, parse_response, reconstruct_response, get_cache_control, compress_response

HEADER_DELIMITER = b'\r\n\r\n'

class ProcessingStates(Enum):
    TLS_HANDSHAKE = 'TLS_HANDSHAKE'
    READ_REQUEST = 'READ_REQUEST'
    CONNECT_BACKEND = 'CONNECT_BACKEND'
    WRITE_BACKEND = 'WRITE_BACKEND'
    READ_BACKEND = 'READ_BACKEND'
    WRITE_CLIENT = 'WRITE_CLIENT'
    CLEANUP = 'CLEANUP'

class ConnectionContext:
    FAILED_SERVERS = {}
    FAILURE_THRESHOLD: int
    MAX_RETRIES: int
    CACHE: Cache
    LOAD_BALANCER: LoadBalancer
    TIMEOUT: int

    def __init__(self, selector: selectors.BaseSelector, 
                sock: ssl.SSLSocket, 
                addr: tuple) -> None:
        self.selector = selector

        self.client_sock = sock
        self.client_addr = addr

        self.backend_sock: socket.socket | None = None
        self.backend_addr: tuple[str, int] | None = None

        self.state = ProcessingStates.TLS_HANDSHAKE
        self._init_connection_info()
        self.last_active = time.time()
    
    def _init_connection_info(self) -> None:
        self.request_buffer: bytes = b''
        self.response_buffer: bytes = b''

        self.request_content_length = 0 # implement max buffer size to prevent malicious attacks?
        self.response_content_length = 0

        self.request_header_parsed = False
        self.response_header_parsed = False

        self._retries = 0

    def process_events(self, mask: int) -> None: # "blind" method that does whatever based on the state of the socket
        self.last_active = time.time()

        match (self.state, mask):
            case (ProcessingStates.TLS_HANDSHAKE, m) if m & (selectors.EVENT_READ | selectors.EVENT_WRITE):
                self._handshake()
            case (ProcessingStates.READ_REQUEST, m) if m & selectors.EVENT_READ:
                self._read_request()

            case (ProcessingStates.CONNECT_BACKEND, m) if m & selectors.EVENT_WRITE:
                self._confirm_backend_conn()

            case (ProcessingStates.WRITE_BACKEND, m) if m & selectors.EVENT_WRITE:
                self._write_request()

            case (ProcessingStates.READ_BACKEND, m) if m & selectors.EVENT_READ:
                self._read_response()

            case (ProcessingStates.WRITE_CLIENT, m) if m & selectors.EVENT_WRITE:
                self._write_client()
        
        if self.state == ProcessingStates.CLEANUP:
            self._close()
    
    def _handshake(self) -> None:
        print('starting TLS handshake')
        try:
            self.client_sock.do_handshake()
        except ssl.SSLWantReadError:
            self.selector.modify(self.client_sock, selectors.EVENT_READ, self)
            return
        except ssl.SSLWantWriteError:
            self.selector.modify(self.client_sock, selectors.EVENT_WRITE, data=self)
            return
        except Exception as e:
            print(f'An unexpected exception occurred on TLS handshake: {e}')
            self._close()
            return
        
        self.state = ProcessingStates.READ_REQUEST
        self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self)
    
    def _read_request(self) -> None:
        """
        Reads from client_sock into request_buffer
        checks for header delimiter
        if request_headers found -> parse -> check cache -> (connect backend or write client)
        """
        print('reading request')
        try:
            data = self.client_sock.recv(4096)
        except (BlockingIOError, ssl.SSLWantReadError):
            return
        except Exception:
            self._close()
            return
        
        if data:
            self.request_buffer += data
        else:
            self._close()
            return
        
        if HEADER_DELIMITER in self.request_buffer:
            if not self.request_header_parsed:
                self._parse_request_headers()

            total_size = self.request_head_raw_length + len(HEADER_DELIMITER) + self.request_content_length
            if len(self.request_buffer) >= total_size:
                self._finalize_request_parsing()
    
    def _parse_request_headers(self):
        request_head_raw, _, _ = self.request_buffer.partition(HEADER_DELIMITER)
        self.request_head_raw_length = len(request_head_raw)

        try:
            self.request_line, self.request_headers = parse_request(request_head_raw)
        except ValueError:
            self.response_buffer = b'400 bad request'
            self._set_write_client_state()
            return

        self.method, self.path = self.request_line.split()[:2]
        self.request_headers_lower = {k.lower(): v.lower() for k, v in self.request_headers.items()}
        self.request_content_length = int(self.request_headers_lower.get('content-length', 0))

        self.keepalive = self.request_headers_lower.get('connection') != 'close'
        
        keys_to_remove = [k for k in self.request_headers if k.lower() == 'connection'] # no need to keep-alive on the back end: hop-by-hop header
        for k in keys_to_remove: 
            self.request_headers.pop(k, None)

        if message := ConnectionContext.CACHE.get_message(self.method, self.path):
            print('Cache hit')
            self.response_buffer = message
            self._set_write_client_state()
            return

        self.request_header_parsed = True

    def _finalize_request_parsing(self):
        self.request_headers['X-Forwarded-For'] = self.client_addr[0]
        self.request_headers['X-Forwarded-Proto'] = 'https'
        
        request_body = self.request_buffer[self.request_head_raw_length + len(HEADER_DELIMITER):]
        self.request_buffer = reconstruct_request(self.request_line, self.request_headers, request_body)
        
        if not self.backend_sock:
            self._init_backend_conn()
        else:
            self.selector.modify(self.backend_sock, selectors.EVENT_WRITE, data=self)
            self.selector.unregister(self.client_sock)
            self.state = ProcessingStates.WRITE_BACKEND

    def _confirm_backend_conn(self) -> None:
        if self.backend_sock:
            err = self.backend_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                self.state = ProcessingStates.WRITE_BACKEND
                return
        # if you reach past this point, it means ur connection has failed
        print('Backend connection failed')
        
        if self.backend_addr:
            ConnectionContext.LOAD_BALANCER._decrement_connection(self.backend_addr) # make sure to avoid leaks on the load balancer
            
            ConnectionContext.FAILED_SERVERS[self.backend_addr] = ConnectionContext.FAILED_SERVERS.get(self.backend_addr, 0) + 1
            if ConnectionContext.FAILED_SERVERS[self.backend_addr] >= ConnectionContext.FAILURE_THRESHOLD:
                print(f"Removing failing server {self.backend_addr}")
                ConnectionContext.LOAD_BALANCER._remove_server(self.backend_addr)
                del ConnectionContext.FAILED_SERVERS[self.backend_addr]
            
            self.backend_addr = None

        if self.backend_sock:
            try:
                self.selector.unregister(self.backend_sock)
                self.backend_sock.close()
            except (KeyError, OSError): 
                pass
            self.backend_sock = None

        if self._retries < ConnectionContext.MAX_RETRIES:
            self._retries += 1
            print(f"Retrying backend... ({self._retries})")
            self._init_backend_conn()
        else:
            self.response_buffer = b'502 bad gateway'
            self._set_write_client_state()
    
    def _write_request(self) -> None:
        """
        Sends request_buffer to backend_sock
        if buffer empty -> update selector to read response -> state to READ_BACKEND
        """
        print('writing request')
        if self.backend_sock and self.request_buffer:
            try:
                sent = self.backend_sock.send(self.request_buffer) # .send returns the # of bytes sent
                if not sent:
                    return # CRITICAL: THIS IS AN ERROR, IT MEANS THE BACKEND HAS NOT BEEN CONNECTED
                self.request_buffer = self.request_buffer[sent:] # so use that info to clear the buffer
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except (BrokenPipeError, ConnectionResetError):
                print("Backend closed connection unexpectedly")
                self._close_backend_only()
                self.response_buffer = b'502 bad gateway'
                self._set_write_client_state()
                return
        
        if self.backend_sock and not self.request_buffer:
            self.selector.modify(self.backend_sock, selectors.EVENT_READ, data=self) # if everything is sent, change back to EVENT_READ to avoid excessively pinging
            self.state = ProcessingStates.READ_BACKEND

    def _read_response(self) -> None:
        try:
            data = self.backend_sock.recv(4096) # type: ignore
        except BlockingIOError:
            return
        except Exception:
            self.response_buffer = b'502 bad gateway'
            self._set_write_client_state()
            return
        
        if data:
            self.response_buffer += data
        else:
            if not self.response_header_parsed:
                self.response_buffer = b'502 bad gateway'
            self._set_write_client_state()
            return

        if HEADER_DELIMITER in self.response_buffer and not self.response_header_parsed:
            self._parse_response_headers()

        if self.response_header_parsed:
            total_len = self.response_head_raw_length + len(HEADER_DELIMITER) + self.response_content_length
            if len(self.response_buffer) >= total_len:
                self._finalize_response()

    def _parse_response_headers(self):
        response_head_raw, _, _ = self.response_buffer.partition(HEADER_DELIMITER)
        self.response_head_raw_length = len(response_head_raw)
        try:
            self.response_line, self.response_headers = parse_response(response_head_raw)
        except ValueError:
            self.response_buffer = b'502 bad gateway'
            self._set_write_client_state()
            return
        
        self.response_headers_lower = {k.lower(): v.lower() for k, v in self.response_headers.items()}
        self.response_content_length = int(self.response_headers_lower.get('content-length', 0))
        self.response_header_parsed = True

    def _finalize_response(self):
        body = self.response_buffer[self.response_head_raw_length + len(HEADER_DELIMITER):]
        
        if 'accept-encoding' in self.request_headers_lower and 'gzip' in self.request_headers_lower['accept-encoding']:
            if 'content-encoding' not in self.response_headers_lower:
                body = compress_response(body)
                self.response_headers['Content-Encoding'] = 'gzip'
                self.response_headers['Content-Length'] = str(len(body))

        self.response_buffer = reconstruct_response(self.response_line, self.response_headers, body)

        if 'cache-control' in self.response_headers_lower:
            if max_age := get_cache_control(self.response_headers_lower['cache-control']):
                ConnectionContext.CACHE.add_message(self.method, self.path, self.response_buffer, max_age)

        self._set_write_client_state()
    
    def _set_write_client_state(self):
        self._close_backend_only()
        
        try:
            self.selector.modify(self.client_sock, selectors.EVENT_WRITE, data=self)
        except (ValueError, KeyError):
            self.selector.register(self.client_sock, selectors.EVENT_WRITE, data=self)
        self.state = ProcessingStates.WRITE_CLIENT

    def _write_client(self):
        """
        Sends response_buffer to client_sock
        if buffer empty -> state to CLEANUP
        """
        print('writing client')
        if self.client_sock and self.response_buffer:
            try:
                sent = self.client_sock.send(self.response_buffer) # .send returns the # of bytes sent
                if not sent:
                    return # CRITICAL: THIS IS AN ERROR, IT MEANS THE BACKEND HAS NOT BEEN CONNECTED
                self.response_buffer = self.response_buffer[sent:] # so use that info to clear the buffer
            except BlockingIOError:
                pass
            except Exception:
                self.state = ProcessingStates.CLEANUP
                return
        
        if self.client_sock and not self.response_buffer:
            try:
                if self.keepalive:
                    self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self)

                    self.state = ProcessingStates.READ_REQUEST
                    self._init_connection_info()
                    print('keepalive, going back to read request')
                    return
            except AttributeError:
                pass
            except Exception:
                self.state = ProcessingStates.CLEANUP
            print('no keepalive')
            self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self)
            self.state = ProcessingStates.CLEANUP

    def _init_backend_conn(self):
        """
        Asks Load Balancer for an address
        creates socket, sets non-blocking
        connect_ex(),
        registers backend_sock with Selector (WRITE_BACKEND), passing self as data
        pauses client_sock (unregister or remove selectors.EVENT_READ) to stop buffering
        """
        print('initializing backend connection')
        # use _get_server_one() temporarily, all methods in the load balancer return an (IP, Port) tuple where IP is a str and Port is an int
        try:
            self.backend_addr = ConnectionContext.LOAD_BALANCER.get_server(self.client_addr[0]) # type: ignore
            print(f'Got server: {self.backend_addr}')
        except (ValueError, ZeroDivisionError):
            print('CRITICAL: Failed to find backend server')
            self.response_buffer = b'503 service unavailable'
            self._set_write_client_state()
            return
        ConnectionContext.LOAD_BALANCER._increment_connection(self.backend_addr)
        print(ConnectionContext.LOAD_BALANCER.servers_dict)
        if not self.backend_addr:
            ... # CRITICAL: THIS MUST RAISE AN ERROR 503 service unavailable
        
        self.state = ProcessingStates.CONNECT_BACKEND
        self.backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.backend_sock.setblocking(False)
        self.backend_sock.connect_ex(self.backend_addr)

        self.selector.register(self.backend_sock, selectors.EVENT_WRITE, data=self)
        try:
            self.selector.unregister(self.client_sock)
        except KeyError:
            pass

    def _close_backend_only(self):
        if self.backend_sock:
            try:
                self.selector.unregister(self.backend_sock)
                self.backend_sock.close()
            except (KeyError, OSError): 
                pass
            self.backend_sock = None
            
        if self.backend_addr:
            ConnectionContext.LOAD_BALANCER._decrement_connection(self.backend_addr)
            self.backend_addr = None

    def _close(self) -> None:
        print('closing down connection')
        try:
            if self.client_sock:
                try:
                    print('unregistering client socket')
                    self.selector.unregister(self.client_sock)
                except (KeyError, ValueError): 
                    pass
                print('closing client socket')
                self.client_sock.close()
            if self.backend_sock:
                try:
                    print('unregistering backend socket')
                    self.selector.unregister(self.backend_sock)
                except (KeyError, ValueError): 
                    pass
                print('closing backend socket')
                self.backend_sock.close()
            if self.backend_addr:
                ConnectionContext.LOAD_BALANCER._decrement_connection(self.backend_addr)
                self.backend_addr = None
        except Exception as e:
            print(f'error during close: {e}')
        print('everything closed')
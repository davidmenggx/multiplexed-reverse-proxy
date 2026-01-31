import ssl
import time
import socket
import logging
import selectors
from enum import Enum

import responses
from cache import Cache
from load_balancer import LoadBalancer
from connection_pool import ConnectionPool
from utilities import parse_request, reconstruct_request, parse_response, reconstruct_response, get_cache_control, compress_response

LOGGER = logging.getLogger('reverse_proxy')

HEADER_DELIMITER = b'\r\n\r\n'

MAX_HEADER_SIZE = 8192 # 8KB

class ProcessingStates(Enum):
    TLS_HANDSHAKE = 'TLS_HANDSHAKE'
    READ_REQUEST = 'READ_REQUEST'
    CONNECT_BACKEND = 'CONNECT_BACKEND'
    WRITE_BACKEND = 'WRITE_BACKEND'
    READ_BACKEND = 'READ_BACKEND'
    WRITE_CLIENT = 'WRITE_CLIENT'
    CLEANUP = 'CLEANUP'

class ConnectionContext:
    """Opaque object used to store and manage processing states for each client-server connection"""
    FAILED_SERVERS = {}
    FAILURE_THRESHOLD: int
    MAX_RETRIES: int
    CACHE: Cache
    LOAD_BALANCER: LoadBalancer
    TIMEOUT: int
    POOL: ConnectionPool

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
        self.last_active = time.time() # Used to time-out keep-alive connections
    
    def _init_connection_info(self) -> None:
        self.request_buffer: bytes = b''
        self.response_buffer: bytes = b''

        self.request_content_length = 0
        self.response_content_length = 0

        self.request_header_parsed = False
        self.response_header_parsed = False

        self._retries = 0

    def process_events(self, mask: int) -> None:
        """Opaque method that calls the appropriate processing step based on connection and socket states"""
        self.last_active = time.time() # Reset count to time-out for keep-alive connections

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
        """Complete TLS handshake for non-blocking sockets"""
        try:
            self.client_sock.do_handshake()
        except ssl.SSLWantReadError:
            self.selector.modify(self.client_sock, selectors.EVENT_READ, self)
            return
        except ssl.SSLWantWriteError:
            self.selector.modify(self.client_sock, selectors.EVENT_WRITE, data=self)
            return
        except Exception as e:
            LOGGER.warning(f'An unexpected exception occurred on TLS handshake: {e}')
            self._close()
            return
        
        self.state = ProcessingStates.READ_REQUEST
        self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self)
    
    def _read_request(self) -> None:
        """Reads from client_sock into request_buffer until header delimiter reached and full message loaded"""
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
            if len(self.request_buffer) > MAX_HEADER_SIZE:
                self.response_buffer = responses.header_too_large()
                self._set_write_client_state()
                return
            
            if not self.request_header_parsed:
                self._parse_request_headers()
            
            if self.state == ProcessingStates.WRITE_CLIENT:
                    return

            total_size = self.request_head_raw_length + len(HEADER_DELIMITER) + self.request_content_length
            if len(self.request_buffer) >= total_size:
                self._finalize_request_parsing()
        elif len(self.request_buffer) > MAX_HEADER_SIZE: # Prevent excessive message size
            self.response_buffer = responses.header_too_large()
            self._set_write_client_state()
            return
        
    def _parse_request_headers(self):
        """Parses request header and checks if message already exists in cache, immediately writing client on cache hit"""
        request_head_raw, _, _ = self.request_buffer.partition(HEADER_DELIMITER)
        self.request_head_raw_length = len(request_head_raw)

        try:
            self.request_line, self.request_headers = parse_request(request_head_raw)
        except ValueError:
            self.response_buffer = responses.bad_request()
            self._set_write_client_state()
            return

        self.method, self.path, protocol_version = self.request_line.split()
        self.request_headers_lower = {k.lower(): v.lower() for k, v in self.request_headers.items()}
        self.request_content_length = int(self.request_headers_lower.get('content-length', 0))

        if protocol_version != 'HTTP/1.1':
            self.response_buffer = responses.http_version_not_supported()
            self._set_write_client_state()
            return

        self.keepalive = self.request_headers_lower.get('connection') != 'close'
        
        keys_to_remove = [k for k in self.request_headers if k.lower() == 'connection'] # No need to keep-alive on the back-end
        for k in keys_to_remove: 
            self.request_headers.pop(k, None)

        if message := ConnectionContext.CACHE.get_message(self.method, self.path):
            self.response_buffer = message
            self._set_write_client_state()
            return

        self.request_header_parsed = True

    def _finalize_request_parsing(self):
        """Add forwarding headers and initialize backend connection, if not yet created"""
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
    
    def _write_request(self) -> None:
        """Write request to backend server"""
        if self.backend_sock and self.request_buffer:
            try:
                sent = self.backend_sock.send(self.request_buffer) # Returns the # of bytes sent
                if not sent:
                    LOGGER.critical("Failed to write request to backend")
                    self._close_backend_only()
                    self.response_buffer = responses.bad_gateway()
                    self._set_write_client_state()
                    return
                self.request_buffer = self.request_buffer[sent:] # Clear the buffer after sneding
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except (BrokenPipeError, ConnectionResetError):
                LOGGER.critical("Backend closed connection unexpectedly")
                self._close_backend_only()
                self.response_buffer = responses.bad_gateway()
                self._set_write_client_state()
                return
        
        if self.backend_sock and not self.request_buffer:
            self.selector.modify(self.backend_sock, selectors.EVENT_READ, data=self)
            self.state = ProcessingStates.READ_BACKEND

    def _read_response(self) -> None:
        """Reads from backend sock into response_buffer until header delimiter reached and full message loaded"""
        try:
            data = self.backend_sock.recv(4096) # type: ignore
        except BlockingIOError:
            return
        except Exception:
            self.response_buffer = responses.bad_gateway()
            self._set_write_client_state()
            return
        
        if data:
            self.response_buffer += data
        else:
            if not self.response_header_parsed:
                self.response_buffer = responses.bad_gateway()
            self._set_write_client_state()
            return

        if HEADER_DELIMITER in self.response_buffer and not self.response_header_parsed:
            self._parse_response_headers()

        if self.response_header_parsed:
            total_len = self.response_head_raw_length + len(HEADER_DELIMITER) + self.response_content_length
            if len(self.response_buffer) >= total_len:
                self._finalize_response()

    def _parse_response_headers(self):
        """Parses response headers"""
        response_head_raw, _, _ = self.response_buffer.partition(HEADER_DELIMITER)
        self.response_head_raw_length = len(response_head_raw)
        try:
            self.response_line, self.response_headers = parse_response(response_head_raw)
        except ValueError:
            self.response_buffer = responses.bad_gateway()
            self._set_write_client_state()
            return
        
        self.response_headers_lower = {k.lower(): v.lower() for k, v in self.response_headers.items()}
        self.response_content_length = int(self.response_headers_lower.get('content-length', 0))
        self.response_header_parsed = True

    def _finalize_response(self):
        """Encode message and add to cache, if specified"""
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
        """
        Helper method to immediately write the client
        Used to immediately return cached messages or error messages
        """
        self._close_backend_only()
        
        try:
            self.selector.modify(self.client_sock, selectors.EVENT_WRITE, data=self)
        except (ValueError, KeyError):
            self.selector.register(self.client_sock, selectors.EVENT_WRITE, data=self)
        self.state = ProcessingStates.WRITE_CLIENT

    def _write_client(self):
        """Write server response to client"""
        if self.client_sock and self.response_buffer:
            try:
                sent = self.client_sock.send(self.response_buffer)
                if not sent:
                    self.state = ProcessingStates.CLEANUP
                    return
                self.response_buffer = self.response_buffer[sent:]
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
                    return
            except AttributeError:
                pass
            except Exception:
                self.state = ProcessingStates.CLEANUP
            self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self)
            self.state = ProcessingStates.CLEANUP

    def _init_backend_conn(self):
        """Fetches backend address from load balancer and registers to selector"""
        try:
            self.backend_addr = ConnectionContext.LOAD_BALANCER.get_server(self.client_addr[0]) # type: ignore
        except (ValueError, ZeroDivisionError):
            LOGGER.critical('Failed to find backend server')
            self.response_buffer = responses.service_unavailable()
            self._set_write_client_state()
            return
        if not self.backend_addr:
            LOGGER.critical('Failed to find backend server')
            self.response_buffer = responses.service_unavailable()
            self._set_write_client_state()
            return
        ConnectionContext.LOAD_BALANCER.increment_connection(self.backend_addr)
        
        self.backend_sock = ConnectionContext.POOL.get_connection(self.backend_addr)
        self.state = ProcessingStates.CONNECT_BACKEND

        self.selector.register(self.backend_sock, selectors.EVENT_WRITE, data=self)
        try:
            self.selector.unregister(self.client_sock)
        except KeyError:
            pass
    
    def _confirm_backend_conn(self) -> None:
        """Check if backend connection specified is active, retrying if not"""
        if self.backend_sock:
            err = self.backend_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                self.state = ProcessingStates.WRITE_BACKEND
                return
        # If you reach past this point, it means the connection has failed
        LOGGER.warning('Backend connection failed')
        
        if self.backend_addr:
            ConnectionContext.LOAD_BALANCER.decrement_connection(self.backend_addr)
            
            ConnectionContext.FAILED_SERVERS[self.backend_addr] = ConnectionContext.FAILED_SERVERS.get(self.backend_addr, 0) + 1 # Update failed server count to remove servers who exceed a failure threshold
            if ConnectionContext.FAILED_SERVERS[self.backend_addr] >= ConnectionContext.FAILURE_THRESHOLD:
                LOGGER.warning(f"Removing failing server {self.backend_addr}")
                ConnectionContext.LOAD_BALANCER.remove_server(self.backend_addr)
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
            LOGGER.debug(f"Retrying backend... ({self._retries})")
            self._init_backend_conn()
        else:
            self.response_buffer = responses.bad_gateway()
            self._set_write_client_state()

    def _close_backend_only(self):
        """Helper method to close the backend if connection fails"""
        if self.backend_sock:
            try:
                self.selector.unregister(self.backend_sock)
                self.POOL.release_connection(self.backend_addr, self.backend_sock) # type: ignore
            except (KeyError, OSError): 
                pass
            self.backend_sock = None
            
        if self.backend_addr:
            ConnectionContext.LOAD_BALANCER.decrement_connection(self.backend_addr)
            self.backend_addr = None

    def _close(self) -> None:
        """Close and unregister client and backend socket"""
        try:
            if self.client_sock:
                try:
                    self.selector.unregister(self.client_sock)
                except (KeyError, ValueError): 
                    pass
                self.client_sock.close()
            if self.backend_sock:
                try:
                    self.selector.unregister(self.backend_sock)
                except (KeyError, ValueError): 
                    pass
                self.POOL.release_connection(self.backend_addr, self.backend_sock) # type: ignore
            if self.backend_addr:
                ConnectionContext.LOAD_BALANCER.decrement_connection(self.backend_addr)
                self.backend_addr = None
        except Exception as e:
            LOGGER.critical(f'Error closing {self.client_addr}: {e}')
import ssl
import time
import errno
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
            data: bytes = self.client_sock.recv(4096)
        except (BlockingIOError, ssl.SSLWantReadError): # if for some reason no data is found, do nothing
            return
        except Exception:
            self._close()
            return
        
        if data:
            self.request_buffer += data
        else: # no data = end of connection, so close
            self._close()
            return
        
        if HEADER_DELIMITER in self.request_buffer:
            if not self.request_header_parsed:
                request_head_raw, _, _ = self.request_buffer.partition(HEADER_DELIMITER)
                self.request_head_raw_length = len(request_head_raw)

                try:
                    request_line, request_headers = parse_request(request_head_raw) # this will be in the original casing
                except ValueError:
                    print('malformed request, sending back 400')
                    self.response_buffer = b'400 bad request'
                    self._set_write_client_state()
                    return # CRITICAL: COULD NOT PARSE ERROR 400 BAD REQUEST
                
                self.method, self.path = request_line.split()[:2]

                # maybe do validation on the request version ? or not because right now i have no version
                
                self.request_headers_lower = {key.lower(): value.lower() for key, value in request_headers.items()}

                try:
                    self.request_content_length: int = int(self.request_headers_lower.get('content-length', 0))
                except Exception as e:
                    print(f'Could not parse content length: {e}')
                    return
                
                if 'connection' in self.request_headers_lower:
                    self.keepalive = True if self.request_headers_lower.get('connection') != 'close' else False
                    _request_connection_key = next(k for k in request_headers if k.lower() == 'connection')
                    request_headers.pop(_request_connection_key)
                    self.request_headers_lower.pop('connection')
                
                if message := ConnectionContext.CACHE.get_message(self.method, self.path): # get_request either returns the message if it is found, or empty bytes if cache miss (or timeout on cache hit)
                    # maybe i need to do something like loading the message? what do i load to?
                    print('cache hit')
                    self.response_buffer = message
                    self._set_write_client_state()
                    return
                
                self.request_header_parsed = True
                print('finished parsing header')
            
            if len(self.request_buffer) < self.request_head_raw_length + len(HEADER_DELIMITER) + self.request_content_length:
                return # this means the message hasn't fully been read yet
            
            # moving past this part means the message has been fully read
            
            # reconstruct request_headers (add x-forward, x-proto, strip connection keep alive, etc.)
            request_headers['X-Forwarded-For'] = f'{self.client_addr[0].replace("'", '')}' # type: ignore
            request_headers['X-Forwarded-Proto'] = 'https'

            request_body = self.request_buffer[self.request_head_raw_length + len(HEADER_DELIMITER):]
            self.request_buffer = reconstruct_request(request_line, request_headers, request_body)
            
            if not self.backend_sock: # IMPORTANT: IF THE BACKEND SOCK ALR EXISTS, SKIP STRAIGHT TO WRITE_BACKEND
                self._init_backend_conn()
            else: # backend socket could alr exist if we are keep aliving
                self.selector.modify(self.backend_sock, selectors.EVENT_WRITE, data=self)
                self.selector.unregister(self.client_sock)
                self.state = ProcessingStates.WRITE_BACKEND
            # more logic here

            print(self.request_buffer)
    
    def _confirm_backend_conn(self) -> None:
        """
        Called when backend_sock becomes writable (connection established)
        checks SO_ERROR
        if valid => update selector to write request -> state to WRITE_BACKEND
        """
        print('finishing connection')
        if self.backend_sock and not (error_code := self.backend_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)):
            # if you reach this point, it means you have finished the connection to the backend
            self.state = ProcessingStates.WRITE_BACKEND
        elif self._retries < ConnectionContext.MAX_RETRIES:
            print(f'CRITICAL: Error occured when connecting to backend: {errno.errorcode.get(error_code)}') # errno for more descriptive error messages
            
            ConnectionContext.FAILED_SERVERS[self.backend_addr] = ConnectionContext.FAILED_SERVERS.get(self.backend_addr, 0) + 1

            if ConnectionContext.FAILED_SERVERS[self.backend_addr] > ConnectionContext.FAILURE_THRESHOLD and self.backend_addr:
                try:
                    print(f'CRITICAL: Failure threshold {ConnectionContext.FAILURE_THRESHOLD} hit on server {self.backend_addr}, removing')
                    ConnectionContext.LOAD_BALANCER._remove_server(self.backend_addr)
                    del ConnectionContext.FAILED_SERVERS[self.backend_addr]
                except KeyError:
                    pass

            print(ConnectionContext.FAILED_SERVERS)
            if self.backend_sock:
                try:
                    self.selector.unregister(self.backend_sock)
                    self.backend_sock.close()
                except (KeyError, OSError):
                    pass
                self.backend_sock = None
            if self.backend_addr:
                self.backend_addr = None
            
            print(f'Trying again with new backend. Attempt {self._retries}/{ConnectionContext.MAX_RETRIES}')
            self._retries += 1
            self._init_backend_conn()
            return
        else:
            print('502 bad gateway')
            self.response_buffer = b'502 bad gateway'
            self._set_write_client_state()
            return
            # at this point return bad gateway
    
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
            except BlockingIOError:
                pass
        
        if self.backend_sock and not self.request_buffer:
            self.selector.modify(self.backend_sock, selectors.EVENT_READ, data=self) # if everything is sent, change back to EVENT_READ to avoid excessively pinging
            self.state = ProcessingStates.READ_BACKEND

    def _read_response(self) -> None:
        """
        Reads from backend_sock into response_buffer
        parses response_headers for Content-Length
        if full body received -> close backend -> state to WRITE_CLEINT
        """
        print('reading response')
        try:
            if self.backend_sock:
                data: bytes = self.backend_sock.recv(4096)
        except BlockingIOError: # if for some reason no data is found, do nothing
            return
        
        if data:
            self.response_buffer += data
        else: # DO I NEED THIS LINE?
            self._close()
            return
        
        if HEADER_DELIMITER in self.response_buffer:
            if not self.response_header_parsed:
                response_head_raw, _, response_remaining_bytes = self.response_buffer.partition(HEADER_DELIMITER)
                self.response_head_raw_length = len(response_head_raw)

                try:
                    self.response_line, self.response_headers = parse_response(response_head_raw)
                except ValueError:
                    return # CRITICAL: COULD NOT PARSE ERROR INTERNAL SERVER ERROR
                
                self.response_headers_lower = {key.lower(): value.lower() for key, value in self.response_headers.items()} # you need self here since you'll check it again for gzipping/cache

                try:
                    self.response_content_length: int = int(self.response_headers_lower.get('content-length', 0))
                except Exception as e:
                    print(f'Could not parse content length: {e}')
                    return
                
                self.response_header_parsed = True

            # after the response has been loaded:
            # look up content length and make sure it has been loaded fully
            if len(self.response_buffer) < self.response_head_raw_length + len(HEADER_DELIMITER) + self.response_content_length:
                return
            
            # if no compression, just return the response buffer, otherwise i will need to reconstruct it
            response_body = self.response_buffer[self.response_head_raw_length + len(HEADER_DELIMITER):]

            # think about gzipping (look up accept-encoding)
            if 'accept-encoding' in self.request_headers_lower and 'content-encoding' not in self.response_headers_lower:
                if 'gzip' in self.request_headers_lower['accept-encoding']:
                    response_body = compress_response(response_body)
                    self.response_headers['Content-Length'] = str(len(response_body))
                    self.response_headers['Content-Encoding'] = 'gzip'

            self.response_buffer = reconstruct_response(self.response_line, self.response_headers, response_body)

            if 'cache-control' in self.response_headers_lower:
                if max_age := get_cache_control(self.response_headers_lower['cache-control']):
                    ConnectionContext.CACHE.add_message(self.method, self.path, self.response_buffer, max_age)
                    print('added to cache')

            # print(self.response_buffer)
            self._set_write_client_state()
    
    def _set_write_client_state(self):
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
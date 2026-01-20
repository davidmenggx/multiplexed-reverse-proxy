import ssl
import socket
import selectors
from enum import Enum

from load_balancer import LoadBalancer
from cache import Cache
from utilities import parse_request

LOAD_BALANCER = LoadBalancer()

CACHE = Cache()

HEADER_DELIMITER = b'\r\n\r\n'

class ProcessingStates(Enum):
    READ_REQUEST = 'READ_REQUEST'
    CONNECT_BACKEND = 'CONNECT_BACKEND'
    WRITE_BACKEND = 'WRITE_BACKEND'
    READ_BACKEND = 'READ_BACKEND'
    WRITE_CLIENT = 'WRITE_CLIENT'
    CLEANUP = 'CLEANUP'

# FOR KEEPALIVE, MAKE IT SO THAT INSTEAD OF GOING FROM WRITE_CLIENT => CLEANUP, MAKE IT LOOP BACK TO READ_REQUEST
# THEN RESET ALL OF THE BUFFERS, BUT DO NOT RESET THE SOCKETS

class ConnectionContext:
    def __init__(self, selector: selectors.BaseSelector, 
                sock: socket.socket, 
                addr: socket.AddressFamily,
                context: ssl.SSLContext) -> None:
        self.selector: selectors.BaseSelector = selector

        self.client_sock: ssl.SSLSocket = context.wrap_socket(sock, server_side=True) # server side = True is needed for the server handshake
        self.client_addr: socket.AddressFamily = addr

        self.backend_sock: socket.socket | None = None  # THIS IS CREATED WHEN A BACKEND CONNECTION IS MADE
        self.backend_addr: tuple | None = None  # THIS IS CREATED WHEN A BACKEND CONNECTION IS MADE

        self.state = ProcessingStates.READ_REQUEST
        self.request_buffer: bytes = b''
        self.response_buffer: bytes = b''

        self.request_content_length = 0 # implement max buffer size to prevent malicious attacks?
        self.response_content_length = 0

        self.header_parsed = False
        
    
    def process_events(self, mask: int) -> None: # "blind" method that does whatever based on the state of the socket
        match (self.state, mask):
            case (ProcessingStates.READ_REQUEST, m) if m & selectors.EVENT_READ:
                self._read_request()

            case (ProcessingStates.CONNECT_BACKEND, m) if m & selectors.EVENT_WRITE:
                self._finish_connection()

            case (ProcessingStates.WRITE_BACKEND, m) if m & selectors.EVENT_WRITE:
                self._write_request()

            case (ProcessingStates.READ_BACKEND, m) if m & selectors.EVENT_READ:
                self._read_response()

            case (ProcessingStates.WRITE_CLIENT, m) if m & selectors.EVENT_WRITE:
                self._write_client()
        
        if self.state == ProcessingStates.CLEANUP:
            self._close()
    
    def _read_request(self) -> None:
        """
        Reads from client_sock into request_buffer
        checks for header delimiter
        if headers found -> parse -> check cache -> (connect backend or write client)
        """
        try:
            data: bytes = self.client_sock.recv(4096)
        except BlockingIOError: # if for some reason no data is found, do nothing
            return
        
        if data:
            self.request_buffer += data
        else: # no data = end of connection, so close
            self._close()
            return
        
        if HEADER_DELIMITER in self.request_buffer:
            if not self.header_parsed:
                request_head_raw, _, request_remaining_bytes = self.request_buffer.partition(HEADER_DELIMITER)
                self.head_raw_length = len(request_head_raw)

                ((self.method, self.path, self.version), self.headers) = parse_request(request_head_raw) # all will be returned in lowercase

                if message := CACHE.get_request(self.method, self.path): # get_request either returns the message if it is found, or empty bytes if cache miss (or timeout on cache hit)
                    # maybe i need to do something like loading the message? what do i load to?
                    self.state = ProcessingStates.WRITE_CLIENT
                    self.response_buffer = message
                    self.selector.modify(self.client_sock, selectors.EVENT_WRITE, data=self)
                    return

                try:
                    self.request_content_length: int = int(self.headers.get('content-length', 0))
                except Exception as e:
                    print(f'Could not parse content length: {e}')
                    return
                
                self.header_parsed = True
            
            if len(self.request_buffer) < self.head_raw_length + len(HEADER_DELIMITER) + self.request_content_length:
                return # this means the message hasn't fully been read yet
            else:
                # reconstruct headers (add x-forward, x-proto, etc.)
                self.state = ProcessingStates.CONNECT_BACKEND
                if not self.backend_sock: # IMPORTANT: IF THE BACKEND SOCK ALR EXISTS, SKIP STRAIGHT TO WRITE_BACKEND
                    self._init_backend_conn()
                ... # this means the message has fully been read, move on to initializing the backend conn
            
            # more logic here
    
    def _finish_connection(self) -> None:
        """
        Called when backend_sock becomes writable (connection established)
        checks SO_ERROR
        if valid => update selector to write request -> state to WRITE_BACKEND
        """
        ...
    
    def _write_request(self) -> None:
        """
        Sends request_buffer to backend_sock
        if buffer empty -> update selector to read response -> state to READ_BACKEND
        """
        ...
        # if self.request_buffer:
        #     try:
        #         sent = self.client_sock.send(self.request_buffer) # .send returns the # of bytes sent
        #         self.request_buffer = self.request_buffer[sent:] # so use that info to clear the buffer
        #     except BlockingIOError:
        #         pass
        
        # if not self.request_buffer:
        #     self.selector.modify(self.client_sock, selectors.EVENT_READ, data=self) # if everything is sent, change back to EVENT_READ to avoid excessively pinging

    def _read_response(self) -> None:
        """
        Reads from backend_sock into response_buffer
        parses headers for Content-Length
        if full body received -> close backend -> state to WRITE_CLEINT
        """
        ...

    def _write_client(self):
        """
        Sends response_buffer to client_sock
        if buffer empty -> state to CLEANUP
        """
        ...

    def _init_backend_conn(self):
        """
        Asks Load Balancer for an address
        creates socket, sets non-blocking
        connect_ex(),
        registers backend_sock with Selector (WRITE_BACKEND), passing self as data
        pauses client_sock (unregister or remove selectors.EVENT_READ) to stop buffering
        """
        self.backend_addr = LOAD_BALANCER._get_server_one() # use _get_server_one() temporarily, all methods in the load balancer return an (IP, Port) tuple where IP is a str and Port is an int
        self.backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.backend_sock.setblocking(False)
        self.backend_sock.connect_ex(self.backend_addr)
        self.selector.register(self.backend_sock, selectors.EVENT_WRITE, data=self)
        self.selector.unregister(self.client_sock)


    def _check_cache(self):
        """
        Checks cache for current request
        if hit -> Fill response_buffer -> state changes directly to WRITE_CLIENT
        """
        ...

    def _close(self) -> None:
        try:
            if self.client_sock:
                try:
                    self.selector.unregister(self.client_sock)
                except KeyError: 
                    pass
                self.client_sock.close()
            if self.backend_sock:
                try:
                    self.selector.unregister(self.backend_sock)
                except KeyError: 
                    pass
                self.backend_sock.close()
        except Exception as e:
            print(f'error during close: {e}')
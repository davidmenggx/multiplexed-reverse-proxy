import ssl
import socket
import selectors
from enum import Enum

from load_balancer import LoadBalancer

LOAD_BALANCER = LoadBalancer()

class ProcessingStates(Enum):
    READ_REQUEST = 'READ_REQUEST'
    CONNECT_BACKEND = 'CONNECT_BACKEND'
    WRITE_BACKEND = 'WRITE_BACKEND'
    READ_BACKEND = 'READ_BACKEND'
    WRITE_CLIENT = 'WRITE_CLIENT'
    CLEANUP = 'CLEANUP'

class ConnectionContext:
    def __init__(self, selector: selectors.BaseSelector, 
                sock: socket.socket, 
                addr: socket.AddressFamily,
                context: ssl.SSLContext) -> None:
        self.selector: selectors.BaseSelector = selector

        self.client_sock: ssl.SSLSocket = context.wrap_socket(sock, server_side=True) # server side = True is needed for the server handshake
        self.client_addr: socket.AddressFamily = addr

        self.backend_sock: socket.socket | None = None  # THIS IS CREATED WHEN A BACKEND CONNECTION IS MADE
        self.backend_addr: socket.socket | None = None  # THIS IS CREATED WHEN A BACKEND CONNECTION IS MADE

        self.state = ProcessingStates.READ_REQUEST
        self.request_buffer: bytes = b''
        self.response_buffer: bytes = b''

        self.request_content_length = 0
        self.response_content_length = 0
        
    
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
        ...
        # try:
        #     data: bytes = self.client_sock.recv(4096)
        # except BlockingIOError: # if for some reason no data is found, do nothing
        #     return
        
        # if data:
        #     self.request_buffer += data
        #     self.selector.modify(self.client_sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=self) # if there is data to write, update the selector accordingly
        # else: # no data = end of connection, so close
        #     self._close()
    
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

    def _initiate_backend_connection(self):
        """
        Asks Load Balancer for an address
        creates socket, sets non-blocking
        connect_ex(),
        registers backend_sock with Selector (WRITE_BACKEND), passing self as data
        pauses client_sock (unregister or remove selectors.EVENT_READ) to stop buffering
        """
        ...

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
import socket
import selectors

class ConnectionContext:
    def __init__(self, selector: selectors.BaseSelector, sock: socket.socket, addr: socket.AddressFamily) -> None:
        self.selector: selectors.BaseSelector = selector
        self.sock: socket.socket = sock
        self.addr: socket.AddressFamily = addr
        self._buffer: bytes = b''
    
    def process_events(self, mask: int) -> None: # "blind" method that does whatever based on the state of the socket
        if mask & selectors.EVENT_READ:
            self._read()
        
        if mask & selectors.EVENT_WRITE:
            self._write()
    
    def _read(self) -> None:
        try:
            data: bytes = self.sock.recv(4096)
        except BlockingIOError: # if for some reason no data is found, do nothing
            return
        
        if data:
            self._buffer += data
            self.selector.modify(self.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=self) # if there is data to write, update the selector accordingly
        else: # no data = end of connection, so close
            self._close()
    
    def _write(self) -> None:
        if self._buffer:
            try:
                sent = self.sock.send(self._buffer) # .send returns the # of bytes sent
                self._buffer = self._buffer[sent:] # so use that info to clear the buffer
            except BlockingIOError:
                pass
        
        if not self._buffer:
            self.selector.modify(self.sock, selectors.EVENT_READ, data=self) # if everything is sent, change back to EVENT_READ to avoid excessively pinging

    def _close(self) -> None:
        try:
            self.selector.unregister(self.sock)
        except KeyError:
            pass
        self.sock.close()
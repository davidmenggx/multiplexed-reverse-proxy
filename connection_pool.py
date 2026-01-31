import time
import errno
import socket
import logging
import threading
from collections import deque, defaultdict

LOGGER = logging.getLogger('reverse_proxy')

class ConnectionPool:    
    def __init__(self, maxsize: int, maxlifetime: int) -> None:
        self.pool_lock = threading.Lock()
        self.pool: defaultdict[tuple[str, int], deque[tuple[socket.socket, float]]] = defaultdict(deque) # maps (IP, Port) to queue of (backend socket, last used time)
        self.POOL_MAXSIZE = maxsize
        self.MAX_LIFETIME = maxlifetime
    
    def _create_connection(self, addr: tuple[str, int]) -> socket.socket:
        LOGGER.debug(f'Creating new persistent backend socket for server {addr}')
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.setblocking(False)

        err = backend_sock.connect_ex(addr)
        if err not in (0, errno.EINPROGRESS, errno.WSAEWOULDBLOCK):
            raise socket.error(err, "Connect failed")
        
        return backend_sock
    
    def _is_socket_alive(self, sock: socket.socket) -> bool:
        try:
            sock.setblocking(False)
            data = sock.recv(1, socket.MSG_PEEK)
            
            if data == b'':
                return False
        except BlockingIOError:
            return True
        except (ConnectionResetError, OSError):
            return False
        return False # if there is still stale data remaining in the socket, don't use it

    def get_connection(self, addr: tuple[str, int]) -> socket.socket:
        with self.pool_lock:
            if addr in self.pool:
                queue = self.pool[addr]
                while queue:
                    sock, expiration = queue.popleft()
                    if (time.time() - expiration < self.MAX_LIFETIME) and self._is_socket_alive(sock):
                        return sock
                    sock.close()
        return self._create_connection(addr)
    
    def release_connection(self, addr: tuple[str, int], sock: socket.socket):
        try:
            with self.pool_lock:
                if addr in self.pool and len(self.pool[addr]) < self.POOL_MAXSIZE:
                    self.pool[addr].append((sock, time.time()))
                    LOGGER.debug(f'Added connection back to pool for server {addr}')
                else:
                    sock.close()
        except Exception:
            sock.close()
    
    def cleanup(self) -> None:
        LOGGER.debug('Cleaning up connection pool for expired connections')
        current_time = time.time()
        with self.pool_lock:
            for addr in list(self.pool.keys()):
                deque_obj = self.pool[addr]
                new_deque = deque()
                for sock, timestamp in deque_obj:
                    if (current_time - timestamp) < self.MAX_LIFETIME:
                        new_deque.append((sock, timestamp))
                    else:
                        sock.close()
                self.pool[addr] = new_deque

import time
import errno
import socket
import threading
from collections import deque, defaultdict

class ConnectionPool:    
    def __init__(self, maxsize: int, maxlifetime: int) -> None:
        self.pool_lock = threading.Lock()
        self.pool: defaultdict[tuple[str, int], deque[tuple[socket.socket, float]]] = defaultdict(deque) # maps (IP, Port) to queue of (backend socket, last used time)
        self.POOL_MAXSIZE = maxsize
        self.MAX_LIFETIME = maxlifetime
    
    def _create_connection(self, addr: tuple[str, int]) -> socket.socket:
        print('creating persistent backend socket')
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
        print('fetching connection from pool')
        with self.pool_lock:
            if addr in self.pool:
                queue = self.pool[addr]
                while queue:
                    sock, _ = queue.popleft()
                    if self._is_socket_alive(sock):
                        return sock
                    sock.close()
        return self._create_connection(addr)
    
    def release_connection(self, addr: tuple[str, int], sock: socket.socket) -> bool: # boolean flag for success (true) or unsuccessful (false)
        try:
            with self.pool_lock:
                if addr in self.pool and len(self.pool[addr]) < self.POOL_MAXSIZE:
                    self.pool[addr].append((sock, time.monotonic()))
                    print(f'added connection back to pool: {self.pool}')
                else:
                    sock.close()
                return True
        except Exception:
            sock.close()
            return False
    
    def cleanup(self) -> None:
        print('cleaning up connection pool')
        current_time = time.monotonic()
        with self.pool_lock:
            print(f'Number of connections before cleanup: {sum(len(self.pool[server]) for server in self.pool)}')
            for addr in list(self.pool.keys()):
                deque_obj = self.pool[addr]
                new_deque = deque()
                for sock, timestamp in deque_obj:
                    if (current_time - timestamp) < self.MAX_LIFETIME:
                        new_deque.append((sock, timestamp))
                    else:
                        sock.close()
            print(f'Number of connections after cleanup: {sum(len(self.pool[server]) for server in self.pool)}')
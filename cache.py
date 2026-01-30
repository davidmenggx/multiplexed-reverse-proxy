import time

class Cache:
    def __init__(self):
        self.cache = {} # stores (method, path): (message, timeout)
    
    def get_message(self, method: str, path: str) -> bytes:
        if method.lower() != 'post' and (method, path) in self.cache: # MAKE SURE TO CHECK TIME OUT
            if time.time() < self.cache[(method, path)][1]:
                return self.cache[(method, path)][0]
            else:
                self.cache.pop((method, path))
        return b''
    
    def add_message(self, method: str, path: str, message: bytes, max_age: float) -> None:
        self.cache[(method, path)] = (message, time.time() + max_age)
import time

class Cache:
    def __init__(self):
        self.cache = {} # stores (method, path): (message, timeout)
    
    def get_request(self, method: str, path: str) -> bytes:
        if (method, path) in self.cache: # MAKE SURE TO CHECK TIME OUT
            return self.cache[(method, path)][0]
        else:
            return b''
    
    def add_request(self, method: str, path: str, message: bytes, max_age: float) -> None:
        self.cache[(method, path)] = (message, ...) # ADD MAX_AGE TO CURRENT TIME
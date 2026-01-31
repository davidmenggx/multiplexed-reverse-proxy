import time

class Cache:
    """Stores and fetches server responses for performance"""
    def __init__(self):
        self.cache = {} # Maps (method, path) tuple to (message, timeout) tuple
    
    def get_message(self, method: str, path: str) -> bytes:
        """Returns message if found in cache and not expired"""
        if method.lower() != 'post' and (method, path) in self.cache:
            if time.time() < self.cache[(method, path)][1]:
                return self.cache[(method, path)][0]
            else:
                self.cache.pop((method, path))
        return b''
    
    def add_message(self, method: str, path: str, message: bytes, max_age: float) -> None:
        """Adds message to cache with specified expiration time"""
        self.cache[(method, path)] = (message, time.time() + max_age)
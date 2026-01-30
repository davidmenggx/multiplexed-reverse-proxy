import json
import random
import logging
import threading

LOGGER = logging.getLogger('reverse_proxy')

SERVERS_FILEPATH = 'servers.json'

class LoadBalancer:
    def __init__(self, algorithm: str | None = None) -> None:        
        self.algorithm = algorithm or 'LEAST_CONNECTIONS'
        self._lock = threading.Lock()

        try:
            with open('servers.json', 'r') as f:
                data = json.load(f)

            self.servers_list = [
                (s['ip'], s['port']) for s in data['servers']
            ]
            self.servers_dict = {server: 0 for server in self.servers_list}

            self.ROUND_ROBIN_COUNTER = 0
            
        except KeyError as e:
            LOGGER.critical(f'Error: Missing expected key in JSON: {e}')
        except Exception as e:
            LOGGER.critical(f'Initialization failed: {e}')

    def get_server(self, ip: str) -> tuple[str, int]:
        with self._lock:
            if not self.servers_list:
                raise ValueError("No servers available in Load Balancer")
            match self.algorithm:
                case 'LEAST_CONNECTIONS':
                    return self._get_least_connections_server()
                case 'RANDOM':
                    return self._get_random_server()
                case 'IP_HASH':
                    return self._get_ip_hash_server(ip)
                case 'ROUND_ROBIN':
                    return self._get_round_robin_server()
                case _:
                    raise ValueError(f"Unknown algorithm: {self.algorithm}")
    
    def _get_round_robin_server(self) -> tuple[str, int]:
        round_robin_server = self.servers_list[self.ROUND_ROBIN_COUNTER%len(self.servers_list)]
        self.ROUND_ROBIN_COUNTER += 1
        return round_robin_server
    
    def _get_random_server(self) -> tuple[str, int]:
        random_server = random.choice(self.servers_list)
        return random_server

    def _get_least_connections_server(self) -> tuple[str, int]:
        least_connections_server = min(self.servers_dict, key=self.servers_dict.get) # type: ignore
        return least_connections_server

    def _get_ip_hash_server(self, ip: str) -> tuple[str, int]:
        index = hash(ip) % len(self.servers_list)
        ip_hash_server = self.servers_list[index]
        return ip_hash_server
    
    def _add_server(self, server: tuple[str, int]) -> None: # there need to parms here too
        with self._lock:
            if server not in self.servers_dict:
                self.servers_dict[server] = 0
                self.servers_list = list(self.servers_dict.keys())
                LOGGER.info(f'Added server: {server}')
    
    def _remove_server(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                del self.servers_dict[server]
                self.servers_list = list(self.servers_dict.keys())
                LOGGER.info(f'Removed server: {server}')
    
    def _increment_connection(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                self.servers_dict[server] += 1
            else:
                LOGGER.warning(f"Proxy attempts to increment unknown server {server}")
    
    def _decrement_connection(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                self.servers_dict[server] -= 1
                if self.servers_dict[server] < 0:
                    self.servers_dict[server] = 0
                    LOGGER.critical(f"Negative connections detected for {server}")
            else:
                LOGGER.warning(f"Proxy attempts to decrement unknown server {server}")
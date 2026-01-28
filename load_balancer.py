import json
import random
import threading

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
            
            print(self.servers_list)
        except KeyError as e:
            print(f'Error: Missing expected key in JSON: {e}')
        except Exception as e:
            print(f'Initialization failed: {e}')

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
                print(f'Added server: {server}')
    
    def _remove_server(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                del self.servers_dict[server]
                self.servers_list = list(self.servers_dict.keys())
                print(f'LoadBalancer: Removed server {server}')
    
    def _increment_connection(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                self.servers_dict[server] += 1
            else:
                print(f"Warning: Tries to increment unknown server {server}")
    
    def _decrement_connection(self, server: tuple[str, int]) -> None:
        with self._lock:
            if server in self.servers_dict:
                self.servers_dict[server] -= 1
                if self.servers_dict[server] < 0:
                    self.servers_dict[server] = 0
                    print(f"FATAL: Negative connections detected for {server}")
            else:
                print(f"Warning: Tries to decrement unknown server {server}")

if __name__ == '__main__':
    sample_addr = ('127.0.0.1', 8000)

    testing_load_balancer = LoadBalancer('LEAST_CONNECTIONS')
    print(f'All servers: {testing_load_balancer.servers_dict}')

    print('-------')
    
    random_server = testing_load_balancer._get_random_server()
    print(f'Random server: {random_server}')

    print('-------')
    
    round_robin_1 = testing_load_balancer._get_round_robin_server()
    print(f'Round Robin server 1: {round_robin_1}')

    round_robin_2 = testing_load_balancer._get_round_robin_server()
    print(f'Round Robin server 2: {round_robin_2}')

    print('-------')
    
    least_conn_server = testing_load_balancer._get_least_connections_server()
    print(f'Least connections server: {least_conn_server}')

    print('-------')
    
    ip_hash_server = testing_load_balancer._get_ip_hash_server(sample_addr[0])
    print(f'IP hash server for {sample_addr}: {ip_hash_server}')

    print('-------')
    testing_load_balancer._increment_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)
    testing_load_balancer._decrement_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)
    testing_load_balancer._decrement_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)

    print('-------')
    testing_load_balancer._add_server(('1.2.3.4', 8080))
    print(testing_load_balancer.servers_dict)
    print(testing_load_balancer.servers_list)

    print('-------')
    testing_load_balancer._remove_server(('1.2.3.4', 8080))
    print(testing_load_balancer.servers_dict)
    print(testing_load_balancer.servers_list)
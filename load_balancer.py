import json
import random
import hashlib

SERVERS_FILEPATH = 'servers.json'

class LoadBalancer:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(LoadBalancer, cls).__new__(cls)
        return cls._instance

    def __init__(self, algorithm: str | None = None) -> None:
        if self._initialized:
            return
        
        self.algorithm = algorithm or 'LEAST_CONNECTIONS'

        try:
            with open('servers.json', 'r') as f:
                data = json.load(f)

            self.servers_list = [
                (s['ip'], s['port']) for s in data['servers']
            ]
            self.servers_dict = {server: 0 for server in self.servers_list}

            self.ROUND_ROBIN_COUNTER = 0
            
            self.__class__._initialized = True
            print(self.servers_list)
        except KeyError as e:
            print(f'Error: Missing expected key in JSON: {e}')
        except Exception as e:
            print(f'Initialization failed: {e}')

    def get_server(self, ip: str) -> tuple[str, int]:
        match self.algorithm:
            case 'LEAST_CONNECTIONS':
                return self._get_least_connections_server(None)
            case 'RANDOM':
                return self._get_random_server(None)
            case 'IP_HASH':
                return self._get_ip_hash_server(ip)
            case 'ROUND_ROBIN':
                return self._get_round_robin_server(None)
            case _:
                print(f'Fatal: get server failed due to unknown load balancing algorithm: {self.algorithm}')
                raise ValueError
    
    def _get_round_robin_server(self, _) -> tuple[str, int]:
        round_robin_server = self.servers_list[self.ROUND_ROBIN_COUNTER%len(self.servers_list)]
        self.ROUND_ROBIN_COUNTER += 1
        return round_robin_server
    
    def _get_random_server(self, _) -> tuple[str, int]:
        random_server = random.choice(self.servers_list)
        return random_server

    def _get_least_connections_server(self, _) -> tuple[str, int]:
        least_connections_server = min(self.servers_dict, key=self.servers_dict.get) # type: ignore
        return least_connections_server

    def _get_ip_hash_server(self, ip: str) -> tuple[str, int]:
        hash_object = hashlib.md5(ip.encode()) # deterministic hashing, no salt. good
        hash_hex = hash_object.hexdigest()

        index = int(hash_hex, 16) % len(self.servers_list)
        ip_hash_server = self.servers_list[index]
        return ip_hash_server
    
    def _add_server(self, server: tuple[str, int]) -> None: # there need to parms here too
        if server not in self.servers_dict:
            self.servers_dict[server] = 0
            print(f'Added server: {server}')
            self.servers_list = list(self.servers_dict.keys())
    
    def _remove_server(self, server: tuple[str, int]) -> None:
        try:
            del self.servers_dict[server]
            self.servers_list = list(self.servers_dict.keys())
        except KeyError:
            print('FATAL: Server specified does not exist')
        except Exception as e:
            print(f'FATAL: an error occurred while deleting server {server}: {e}')
    
    def _increment_connection(self, server: tuple[str, int]) -> None:
        try:
            self.servers_dict[server] += 1
        except KeyError:
            print('FATAL: Server specified does not exist')
        except Exception as e:
            print(f'FATAL: an error occurred while incrementing server connection count: {e}')
    
    def _decrement_connection(self, server: tuple[str, int]) -> None:
        try:
            self.servers_dict[server] -= 1
            if self.servers_dict[server] < 0:
                self.servers_dict[server] = 0
                print(f'FATAL: server {server} reached negative connections')
        except KeyError:
            print('FATAL: Server specified does not exist')
        except Exception as e:
            print(f'FATAL: an error occurred while decrementing server connection count: {e}')

if __name__ == '__main__':
    sample_addr = ('127.0.0.1', 8000)

    testing_load_balancer = LoadBalancer('LEAST_CONNECTIONS')
    print(f'All servers: {testing_load_balancer.servers_dict}')

    print('-------')
    
    random_server = testing_load_balancer._get_random_server(sample_addr[0])
    print(f'Random server: {random_server}')

    print('-------')
    
    round_robin_1 = testing_load_balancer._get_round_robin_server(sample_addr[0])
    print(f'Round Robin server 1: {round_robin_1}')

    round_robin_2 = testing_load_balancer._get_round_robin_server(sample_addr[0])
    print(f'Round Robin server 2: {round_robin_2}')

    print('-------')
    
    least_conn_server = testing_load_balancer._get_least_connections_server(sample_addr[0])
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
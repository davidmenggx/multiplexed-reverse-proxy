import ast
import json
import random
import hashlib

SERVERS_FILEPATH = 'servers.json'

class LoadBalancer:
    def __init__(self) -> None:
        try:
            with open(SERVERS_FILEPATH, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Error: The servers config file {SERVERS_FILEPATH} was not found.")
        except Exception as e:
            print(f"An error occurred: {e}")

        # store each server as a (IP, PORT tuple) mapped to # connections
        self.servers_dict = {ast.literal_eval(s): 0 for s in data["servers"]} # parse the python tuples into str and int
        self.servers_list = list(self.servers_dict.keys())
        self.ROUND_ROBIN_COUNTER = 0
    
    def _get_server_one(self, _) -> tuple[str, int]: # type: ignore
        # experimental for testing
        try:
            return self.servers_list[0]
        except KeyError:
            print('Could not fetch a server')
    
    def _get_round_robin(self, _) -> tuple[str, int]:
        round_robin_server = self.servers_list[self.ROUND_ROBIN_COUNTER%len(self.servers_list)]
        self.ROUND_ROBIN_COUNTER += 1
        return round_robin_server
    
    def _get_random(self, _) -> tuple[str, int]:
        random_server = random.choice(self.servers_list)
        return random_server

    def _get_least_connections(self, _) -> tuple[str, int]:
        least_connections_server = min(self.servers_dict, key=self.servers_dict.get) # type: ignore
        return least_connections_server

    def _get_ip_hash(self, ip: str) -> tuple[str, int]:
        hash_object = hashlib.md5(ip.encode()) # deterministic hashing, no salt. good
        hash_hex = hash_object.hexdigest()

        index = int(hash_hex, 16) % len(self.servers_list)
        ip_hash_server = self.servers_list[index]
        return ip_hash_server
    
    def _add_server(self) -> None: # there need to parms here too
        ...
    
    def _increment_connection(self, server: tuple[str, int]) -> None:
        try:
            self.servers_dict[server] += 1
        except KeyError:
            print('FATAL: Incorrect server specified')
        except Exception as e:
            print(f'FATAL: an error occurred while incrementing server connection count: {e}')
    
    def _decrement_connection(self, server: tuple[str, int]) -> None:
        try:
            self.servers_dict[server] -= 1
            if self.servers_dict[server] < 0:
                self.servers_dict[server] = 0
                print(f'FATAL: server {server} reached negative connections')
        except KeyError:
            print('FATAL: Incorrect server specified')
        except Exception as e:
            print(f'FATAL: an error occurred while decrementing server connection count: {e}')

if __name__ == '__main__':
    sample_addr = ('127.0.0.1', 8000)

    testing_load_balancer = LoadBalancer()
    print(f'All servers: {testing_load_balancer.servers_dict}')

    print('-------')
    
    random_server = testing_load_balancer._get_random(sample_addr[0])
    print(f'Random server: {random_server}')

    print('-------')
    
    round_robin_1 = testing_load_balancer._get_round_robin(sample_addr[0])
    print(f'Round Robin server 1: {round_robin_1}')

    round_robin_2 = testing_load_balancer._get_round_robin(sample_addr[0])
    print(f'Round Robin server 2: {round_robin_2}')

    print('-------')
    
    least_conn_server = testing_load_balancer._get_least_connections(sample_addr[0])
    print(f'Least connections server: {least_conn_server}')

    print('-------')
    
    ip_hash_server = testing_load_balancer._get_ip_hash(sample_addr[0])
    print(f'IP hash server for {sample_addr}: {ip_hash_server}')

    print('-------')
    testing_load_balancer._increment_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)
    testing_load_balancer._decrement_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)
    testing_load_balancer._decrement_connection(('127.0.0.1', 8080))
    print(testing_load_balancer.servers_dict)
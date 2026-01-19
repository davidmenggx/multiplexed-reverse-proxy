import ast
import json

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
        self.servers = {ast.literal_eval(s): 0 for s in data["servers"]} # parse the python tuples into str and int
    
    def _get_server_one(self) -> tuple[str, int]: # type: ignore
        # experimental for testing
        try:
            return list(self.servers.keys())[0]
        except KeyError:
            print('Could not fetch a server')
    
    def _get_round_robin(self) -> tuple[str, int]:
        ...
    
    def _get_random(self) -> tuple[str, int]:
        ...

    def _get_least_connections(self) -> tuple[str, int]:
        ...

    def _get_ip_hash(self) -> tuple[str, int]:
        ...
import ssl
import socket
import signal
import argparse
import selectors
import threading

from cache import Cache
from load_balancer import LoadBalancer
from connection_context import ConnectionContext

parser = argparse.ArgumentParser(description="Configs for multiplexed reverse proxy")
parser.add_argument('-p', '--port', type=int, default=8443, help='Port for server to run on')
parser.add_argument('-l', '--loadalg', type=str, default='LEAST_CONNECTIONS', help='Choose a load balancing algorithm. Valid options: "LEAST_CONNECTIONS" (default), "IP_HASH", "RANDOM", "ROUND_ROBIN"')
parser.add_argument('-d', '--discovery', type=int, default=49152, help='Port for server to run on')
parser.add_argument('-t', '--threshold', type=int, default=3, help='Max number of failed connections before server is removed from load balancer')
parser.add_argument('-r', '--retries', type=int, default=5, help='Max number of connection retries until error')

args = parser.parse_args()

HOST = ''
PORT = args.port

DISCOVERY_PORT = args.discovery if args.discovery != PORT else 49153

LOAD_BALANCING_ALGORITHM = args.loadalg.upper() 
if LOAD_BALANCING_ALGORITHM not in {'IP_HASH', 'LEAST_CONNECTIONS', 'RANDOM', 'ROUND_ROBIN'}:
    print(f'Error: specified load balancing algorithm {args.loadalg} does not exist, defaulting to least connections')
    LOAD_BALANCING_ALGORITHM = 'LEAST_CONNECTIONS'

ConnectionContext.FAILURE_THRESHOLD = args.threshold
ConnectionContext.MAX_RETRIES = args.retries
ConnectionContext.CACHE = Cache()
ConnectionContext.LOAD_BALANCER = LoadBalancer(algorithm=LOAD_BALANCING_ALGORITHM)

RUNNING = True

def signal_shutdown(_sig, _frame) -> None:
    """Shut down server"""
    global RUNNING
    RUNNING = False

signal.signal(signal.SIGINT, signal_shutdown) # Catch CTRL+C
signal.signal(signal.SIGTERM, signal_shutdown) # Catch kill command

sel = selectors.DefaultSelector()

lsock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

lsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

lsock.bind((HOST, PORT))

lsock.listen()

lsock.setblocking(False)

sel.register(lsock, selectors.EVENT_READ, data=None)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) # use CLIENT_AUTH since i am in the role of the server itself
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

def accept_connection(sock) -> None:
    conn, addr = sock.accept()
    
    ssl_conn = context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
    ssl_conn.setblocking(False)
    
    connection_context = ConnectionContext(sel, ssl_conn, addr)
    
    sel.register(ssl_conn, selectors.EVENT_READ, data=connection_context)
    
    print(f'Accepted and registered connection from {addr}')

def discover_servers() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as discovery_sock:
        discovery_sock.bind((HOST, DISCOVERY_PORT))
        discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery_sock.listen() 

        buffer = ""
        while True:
            conn, addr = discovery_sock.accept() # make sure that i don't need to socket itself, just the information
            # addr is in the form ('IP', PORT, _, _)
            with conn:
                data = conn.recv(1024)
                buffer += data.decode('utf-8')

                while '\r\n' in buffer:
                    message, buffer = buffer.split('\r\n', 1)
                    if message:
                        try:
                            ip, port = message.split(',')
                            if ConnectionContext.LOAD_BALANCER:
                                ConnectionContext.LOAD_BALANCER._add_server((ip, int(port)))
                                print(f'Found server ({ip}, {port})')
                            else:
                                print('Could not find load balancer!')
                        except ValueError:
                            print(f"Malformed message received: {message}")

def main() -> None:
    while RUNNING:
        events = sel.select(timeout=1)
        if not events:
            continue
        for key, mask in events:
            if key.data is None: # the listener has data=None, so when key.data is None, it is a new connection incoming
                accept_connection(key.fileobj)
            else: # otherwise it is a socket that is ready to be processed
                key.data.process_events(mask)
    sel.close()

if __name__ == '__main__':
    print(f'Starting heartbeat thread listening to port {DISCOVERY_PORT}')
    heartbeat_thread = threading.Thread(target=discover_servers, daemon=True)
    heartbeat_thread.start()

    print(f'Starting reverse proxy server listening to port {PORT}')

    main()

    print('Reverse proxy server closed')
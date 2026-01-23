import ssl
import socket
import signal
import argparse
import selectors

from load_balancer import LoadBalancer
from connection_context import ConnectionContext

parser = argparse.ArgumentParser(description="Configs for multiplexed reverse proxy")
parser.add_argument('-p', '--port', type=int, default=8443, help='Port for server to run on')
parser.add_argument('-l', '--loadalg', type=str, default='LEAST_CONNECTIONS', help='Choose a load balancing algorithm. Valid options: "LEAST_CONNECTIONS" (default), "IP_HASH", "RANDOM", "ROUND_ROBIN"')

args = parser.parse_args()

HOST = ''
PORT = args.port

LOAD_BALANCING_ALGORITHM = args.loadalg.upper() 
if LOAD_BALANCING_ALGORITHM not in {'IP_HASH', 'LEAST_CONNECTIONS', 'RANDOM', 'ROUND_ROBIN'}:
    print(f'Error: specified load balancing algorithm {args.loadalg} does not exist, defaulting to least connections')
    LOAD_BALANCING_ALGORITHM = 'LEAST_CONNECTIONS'

LOAD_BALANCER = LoadBalancer(algorithm=LOAD_BALANCING_ALGORITHM)

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
    print(f'Starting reverse proxy server listening to port {PORT}')

    main()

    print('Reverse proxy server closed')
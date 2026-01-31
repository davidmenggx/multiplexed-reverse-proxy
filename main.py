import ssl
import time
import socket
import signal
import logging
import argparse
import selectors
import threading
from ssl import SSLContext, PROTOCOL_TLS_SERVER

from cache import Cache
from load_balancer import LoadBalancer
from connection_pool import ConnectionPool
from connection_context import ConnectionContext

# Parse command line arguments
parser = argparse.ArgumentParser(description="Configs for multiplexed reverse proxy")
parser.add_argument('-p', '--port', type=int, default=8443, help='Port for server to run on')
parser.add_argument('-l', '--loadbal', type=str, default='LEAST_CONNECTIONS', help='Choose a load balancing algorithm. Valid options: "LEAST_CONNECTIONS" (default), "IP_HASH", "RANDOM", "ROUND_ROBIN"')
parser.add_argument('-d', '--discovery', type=int, default=49152, help='Port for server discovery')
parser.add_argument('-t', '--threshold', type=int, default=3, help='Max number of failed connections before server is removed from load balancer')
parser.add_argument('-r', '--retries', type=int, default=5, help='Max number of connection retries until error')
parser.add_argument('-k', '--keepalive', type=float, default=3, help='Duration in seconds before keep-alive connections are timed-out')
parser.add_argument('-m', '--maxsize', type=int, default=10, help='Maximum number of connections in pool for each server')
parser.add_argument('-e', '--expiration', type=float, default=10, help='Expiration time before connections in pool are discarded')
parser.add_argument('-f', '--frequency', type=float, default=10, help='Duration in seconds between connection pool cleaning for expired connections')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose mode')

args = parser.parse_args()

# Validate command line arguments
if not (0 <= args.port <= 65535):
    raise ValueError(f'FATAL: specified port {args.port} does not exist!')

if not (0 <= args.discovery <= 65535):
    raise ValueError(f'FATAL: specified discovery port {args.discovery} does not exist!')

if args.port == args.discovery:
    raise ValueError(f'FATAL: Server and discovery port cannot be the same! Currently both {args.port}')

if args.threshold <= 0:
    raise ValueError(f'FATAL: Server failure threshold must be positive! Currently {args.threshold}')

if args.retries < 0:
    raise ValueError(f'FATAL: Maximum retries cannot be negative! Currently {args.retries}')

if args.keepalive < 0:
    raise ValueError(f'FATAL: Keep-alive time cannot be negative! Currently {args.keepalive}')

if args.maxsize < 0:
    raise ValueError(f'FATAL: Connection pool max-size cannot be negative! Currently {args.maxsize}')

if args.expiration < 0:
    raise ValueError(f'FATAL: Connection pool expiration time cannot be negative! Currently {args.expiration}')

if args.frequency < 0:
    raise ValueError(f'FATAL: Connection pool cleanup frequency cannot be negative! Currently {args.frequency}')

# Server settings
HOST = ''
PORT = args.port

DISCOVERY_PORT = args.discovery

LOAD_BALANCING_ALGORITHM = args.loadbal.upper() 
if LOAD_BALANCING_ALGORITHM not in {'IP_HASH', 'LEAST_CONNECTIONS', 'RANDOM', 'ROUND_ROBIN'}:
    print(f'Error: specified load balancing algorithm {args.loadbal} does not exist, defaulting to least connections!')
    LOAD_BALANCING_ALGORITHM = 'LEAST_CONNECTIONS'

# Initialize ConnectionContext with command line arguments
ConnectionContext.FAILURE_THRESHOLD = args.threshold
ConnectionContext.MAX_RETRIES = args.retries
ConnectionContext.CACHE = Cache()
ConnectionContext.LOAD_BALANCER = LoadBalancer(algorithm=LOAD_BALANCING_ALGORITHM)
ConnectionContext.TIMEOUT = args.keepalive
ConnectionContext.POOL = ConnectionPool(args.maxsize, args.expiration)

# Create logger
LOGGER = logging.getLogger('reverse_proxy')
_console_handler = logging.StreamHandler()
_file_handler = logging.FileHandler('proxy.log')
if args.verbose:
    LOGGER.setLevel(logging.DEBUG)
    _console_handler.setLevel(logging.DEBUG)
    _file_handler.setLevel(logging.DEBUG)
else:
    LOGGER.setLevel(logging.WARNING)
    _console_handler.setLevel(logging.WARNING)
    _file_handler.setLevel(logging.WARNING)

_log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_date_format = "%Y-%m-%dT%H:%M:%SZ" # ISO 8601 style
_formatter = logging.Formatter(fmt=_log_format, datefmt=_date_format)
_console_handler.setFormatter(_formatter)
_file_handler.setFormatter(_formatter)

LOGGER.addHandler(_console_handler)
LOGGER.addHandler(_file_handler)

# Shut the server down
RUNNING = True
def signal_shutdown(_sig, _frame) -> None:
    """Shut down server"""
    global RUNNING
    RUNNING = False
signal.signal(signal.SIGINT, signal_shutdown) # Catch CTRL+C
signal.signal(signal.SIGTERM, signal_shutdown) # Catch kill command

# TLS Protocol
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
context.verify_mode = ssl.CERT_NONE

# Server Connections
sel = selectors.DefaultSelector()

lsock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

lsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    lsock.bind((HOST, PORT))
except OSError as e:
    raise RuntimeError(f"Failed to bind to port {PORT}: {e}")

lsock.listen()

lsock.setblocking(False)

sel.register(lsock, selectors.EVENT_READ, data=None)

def accept_connection(sock) -> None:
    """Accepts client requests, initializes new ConnectionContext, and registers to selector"""
    conn, addr = sock.accept()
    
    ssl_conn = context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
    ssl_conn.setblocking(False)
    
    connection_context = ConnectionContext(sel, ssl_conn, addr)
    
    sel.register(ssl_conn, selectors.EVENT_READ, data=connection_context)
    
    LOGGER.debug(f'Accepted and registered connection from {addr}')

def discover_servers() -> None:
    """
    Discovery thread for server discovery
    Receives HOST,PORT tuples from servers
    Adds server information to load balancer for future connections
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as discovery_sock:
            discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                discovery_sock.bind((HOST, DISCOVERY_PORT))
                discovery_sock.listen() 
                LOGGER.debug(f'Discovery thread listening to port {DISCOVERY_PORT}')
            except OSError as e:
                LOGGER.critical(f"Discovery thread failed to bind port {DISCOVERY_PORT}: {e}")
                return

            buffer = ""
            while RUNNING:
                discovery_sock.settimeout(1.0)
                try:
                    conn, _ = discovery_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                with conn:
                    conn.settimeout(2.0) # Make sure discovery thread does not hang on stalled connection
                    try:
                            data = conn.recv(1024)
                            if not data:
                                continue
                            buffer += data.decode('utf-8')

                            while '\r\n' in buffer:
                                message, buffer = buffer.split('\r\n', 1)
                                if message:
                                    try:
                                        ip, port = message.split(',')
                                        if ConnectionContext.LOAD_BALANCER:
                                            ConnectionContext.LOAD_BALANCER.add_server((ip, int(port)))
                                            LOGGER.debug(f'Registered server: {ip}:{port}')
                                    except ValueError:
                                        LOGGER.warning(f"Ignored malformed discovery msg: {message}")
                    except socket.timeout:
                        LOGGER.warning("Discovery connection timed out")
                    except Exception as e:
                        LOGGER.warning(f"Discovery error: {e}")
    except Exception as e:
        LOGGER.critical(f"Discovery thread crashed: {e}")

def cleanup_pool() -> None:
    """Periodically cleans connection pool for expired connections"""
    while RUNNING:
        time.sleep(args.frequency)
        ConnectionContext.POOL.cleanup()

def main() -> None:
    """
    Manages ready to read sockets depending on state
    If listener socket, registers the new request connection
    If client socket, calls the appropriate method using dispatcher process_events
    Removes persistent connections if keep-alive time expires
    """
    while RUNNING:
        events = sel.select(timeout=1.0)
        for key, mask in events:
            if key.data is None:
                accept_connection(key.fileobj)
            else:
                key.data.process_events(mask)
        current_time = time.time()
        for map_key in list(sel.get_map().values()):
            context = map_key.data
            if context is None:
                continue
            if current_time - context.last_active > ConnectionContext.TIMEOUT:
                LOGGER.debug(f"Connection from {context.client_addr} timed out.")
                context._close()
    sel.close()
    lsock.close()

if __name__ == '__main__':
    discovery_thrad = threading.Thread(target=discover_servers, daemon=True)
    discovery_thrad.start()

    cleanup_thread = threading.Thread(target=cleanup_pool, daemon=True)
    cleanup_thread.start()

    LOGGER.debug(f'Starting reverse proxy server listening to port {PORT}')

    main()

    LOGGER.debug('Reverse proxy server closed')
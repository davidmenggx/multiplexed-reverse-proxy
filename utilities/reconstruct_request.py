def reconstruct_request(request_line: str, request_headers: dict[str, str], body: bytes) -> bytes:
    """Reconstructs request, used to add/remove hop-by-hop headers before forwarding to server"""
    res = f'{request_line}\r\n'.encode('utf-8')

    for header, value in request_headers.items():
        res += f'{header}: {value}\r\n'.encode('utf-8')

    res += b'\r\n'

    if body:
        res += body
    
    return res
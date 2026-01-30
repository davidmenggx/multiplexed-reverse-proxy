def reconstruct_request(request_line: str, request_headers: dict[str, str], body: bytes) -> bytes:
    res = f'{request_line}\r\n'.encode('utf-8')

    for header, value in request_headers.items():
        res += f'{header}: {value}\r\n'.encode('utf-8')

    res += b'\r\n'

    if body:
        res += body
    
    return res
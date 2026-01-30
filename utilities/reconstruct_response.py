def reconstruct_response(response_line: str, response_headers: dict[str, str], body: bytes) -> bytes:
    res = f'{response_line}\r\n'.encode('utf-8')

    for header, value in response_headers.items():
        res += f'{header}: {value}\r\n'.encode('utf-8')

    res += b'\r\n'

    if body:
        res += body
    
    return res

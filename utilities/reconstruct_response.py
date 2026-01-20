def reconstruct_response(response_line: str, response_headers: dict[str, str], body: bytes) -> bytes:
    res = f'{response_line}\r\n'.encode('utf-8')

    for header, value in response_headers.items():
        res += f'{header}: {value}\r\n'.encode('utf-8')

    res += b'\r\n'

    if body:
        res += body
    
    return res

if __name__ == '__main__':
    sample_response_line = 'HTTP/1.1 200 OK'
    sample_response_headers = {
                            'Content-Type': 'application/json',
                            'Content-Length': '9',
                            'Connection': 'Keep-Alive',
                            'Date': 'Tue, 20 Jan 2026 22:21:37 GMT',
                            'Server': 'Python/3.13'
                            }
    sample_body = 'test body'.encode('utf-8')
    print(reconstruct_response(sample_response_line, sample_response_headers, sample_body).decode('utf-8')) # works with casing too

    print('------')

    sample_response_line = 'HTTP/1.1 304 Not Modified'

    sample_response_headers = {
                            'Date': 'Tue, 20 Jan 2026 22:21:37 GMT',
                            'Connection': 'Keep-Alive',
                            'Server': 'Python/3.13',
                            'ETag': '"33a64dfc3531d191" ',
                            'Cache-Control': 'max-age=3600'
                            }

    sample_body = b''
    print(reconstruct_response(sample_response_line, sample_response_headers, sample_body).decode('utf-8'))

    print('------')
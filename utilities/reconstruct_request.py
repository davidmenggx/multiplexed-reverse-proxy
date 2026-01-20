def reconstruct_request(request_line: str, request_headers: dict[str, str], body: bytes) -> bytes:
    res = f'{request_line}\r\n'.encode('utf-8')

    for header, value in request_headers.items():
        res += f'{header}: {value}\r\n'.encode('utf-8')

    res += b'\r\n'

    if body:
        res += body
    
    return res

if __name__ == '__main__':
    sample_request_line = 'POST /index.html HTTP/1.1'
    sample_request_headers = {'Host': 'api.example.com', 
                            'Content-Type': 'application/json', 
                            'Content-Length': '9', 
                            'Accept-Encoding': 'gzip', 
                            'Connection': 'Keep-Alive'
                            }
    sample_body = 'test body'.encode('utf-8')
    print(reconstruct_request(sample_request_line, sample_request_headers, sample_body).decode('utf-8')) # works with casing too

    print('------')

    sample_request_line = 'GET /index.html HTTP/1.1'
    sample_request_headers = {'Host': 'api.example.com', 
                            'Content-Type': 'application/json', 
                            'Content-Length': '0', 
                            'Accept-Encoding': 'gzip', 
                            'Connection': 'Keep-Alive'
                            }
    sample_body = b''
    print(reconstruct_request(sample_request_line, sample_request_headers, sample_body).decode('utf-8'))

    print('------')
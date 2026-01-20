def parse_request(header: bytes) -> tuple[str, dict[str, str]]: # returns (request top line, headers dict) in original casing
    request_line_raw = header.split(b'\r\n')[0]
    request_headers_raw_list = header.split(b'\r\n')[1:]

    if len(request_line_raw.split()) != 3: # make sure all three elements of the request line are present
        raise ValueError('Parse Error - Request Line')

    request_headers_raw_dict = {}
    
    for h in request_headers_raw_list:
        _header = h.split(b': ')

        if len(_header) != 2:
            raise ValueError('Parse Error - Request Headers')
        
        request_headers_raw_dict[_header[0]] = _header[1]
    
    request_line_decoded = request_line_raw.decode('utf-8')

    request_headers_decoded = {key.decode('utf-8'): value.decode('utf-8') for key, value in request_headers_raw_dict.items()}
    
    return request_line_decoded, request_headers_decoded

if __name__ == '__main__': # quick test
    sample_request_header = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 9\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: Keep-Alive"
    ).encode('utf-8')
    print(parse_request(sample_request_header))
    # returns ('GET /index.html HTTP/1.1', {'Host': 'api.example.com', 'Content-Type': 'application/json', 'Content-Length': '9', 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive'})
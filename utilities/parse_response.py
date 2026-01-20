def parse_response(header: bytes) -> tuple[str, dict[str, str]]: # returns (response top line, headers dict) in original casing
    response_line_raw = header.split(b'\r\n')[0]
    response_headers_raw_list = header.split(b'\r\n')[1:]

    response_headers_raw_dict = {}
    
    for h in response_headers_raw_list:
        _header = h.split(b': ')

        if len(_header) != 2:
            raise ValueError('Parse Error - Headers')
        
        response_headers_raw_dict[_header[0]] = _header[1]
    
    response_line_decoded = response_line_raw.decode('utf-8')

    response_headers_decoded = {key.decode('utf-8'): value.decode('utf-8') for key, value in response_headers_raw_dict.items()}
    
    return response_line_decoded, response_headers_decoded

if __name__ == '__main__': # quick test
    sample_success_response_header = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Tue, 20 Jan 2026 13:45:00 GMT\r\n"
        "Server: Apache/2.4.41 (Ubuntu)\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 27\r\n"
        "Connection: keep-alive"
    ).encode('utf-8')
    print(parse_response(sample_success_response_header))
    # returns ('HTTP/1.1 200 OK', {'Date': 'Tue, 20 Jan 2026 13:45:00 GMT', 'Server': 'Apache/2.4.41 (Ubuntu)', 'Content-Type': 'application/json', 'Content-Length': '27', 'Connection': 'keep-alive'})

    sample_error_response_header = (
        "HTTP/1.1 404 Not Found\r\n"
        "Date: Tue, 20 Jan 2026 13:46:12 GMT\r\n"
        "Server: Nginx/1.18.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 50\r\n"
        "Connection: close"
    ).encode('utf-8')
    print(parse_response(sample_error_response_header))
    # returns ('HTTP/1.1 404 Not Found', {'Date': 'Tue, 20 Jan 2026 13:46:12 GMT', 'Server': 'Nginx/1.18.0', 'Content-Type': 'application/json', 'Content-Length': '50', 'Connection': 'close'})
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
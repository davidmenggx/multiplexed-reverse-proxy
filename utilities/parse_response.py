def parse_response(header: bytes) -> tuple[str, dict[str, str]]: # returns (response top line, headers dict) in original casing
    """Parses response header, returning (Response line, Headers dict) tuple"""
    response_line_raw = header.split(b'\r\n')[0]
    response_headers_raw_list = header.split(b'\r\n')[1:]

    response_headers_raw_dict = {}
    
    for h in response_headers_raw_list:
        _header = h.split(b': ')

        if len(_header) != 2:
            raise ValueError('Parse Error - Response Headers')
        
        response_headers_raw_dict[_header[0]] = _header[1]
    
    response_line_decoded = response_line_raw.decode('utf-8')

    response_headers_decoded = {key.decode('utf-8'): value.decode('utf-8') for key, value in response_headers_raw_dict.items()}
    
    return response_line_decoded, response_headers_decoded
from utilities import reconstruct_request

def test_successful_reconstruct_no_body():
    request_line = 'POST /api/public_file.txt HTTP/1.1'
    request_headers = {'Host': 'api.example.com', 'Content-Type': 'application/json', 'Content-Length': '73'}
    body = b''
    expected_reconstruction = b'POST /api/public_file.txt HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 73\r\n\r\n'
    assert reconstruct_request(request_line, request_headers, body) == expected_reconstruction

def test_successful_reconstruct_body():
    request_line = 'POST /api/public_file.txt HTTP/1.1'
    request_headers = {'Host': 'api.example.com', 'Content-Type': 'application/json', 'Content-Length': '73'}
    body = b'Hello World'
    expected_reconstruction = b'POST /api/public_file.txt HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 73\r\n\r\nHello World'
    assert reconstruct_request(request_line, request_headers, body) == expected_reconstruction
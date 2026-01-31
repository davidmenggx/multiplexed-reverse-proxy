from utilities import reconstruct_response

def test_successful_reconstruct_no_body():
    response_line = 'HTTP/1.1 200 OK'
    response_headers = {'Date': 'Fri, 30 Jan 2026 16:08:00 GMT', 'Content-Type': 'text/html', 'Content-Length': '44'}
    body = b''
    assert reconstruct_response(response_line, response_headers, body) == b"HTTP/1.1 200 OK\r\nDate: Fri, 30 Jan 2026 16:08:00 GMT\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n"

def test_successful_reconstruct_body():
    response_line = 'HTTP/1.1 200 OK'
    response_headers = {'Date': 'Fri, 30 Jan 2026 16:08:00 GMT', 'Content-Type': 'text/html', 'Content-Length': '44'}
    body = b'Hello World'
    assert reconstruct_response(response_line, response_headers, body) == b"HTTP/1.1 200 OK\r\nDate: Fri, 30 Jan 2026 16:08:00 GMT\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\nHello World"
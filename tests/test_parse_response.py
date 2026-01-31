import pytest

from utilities import parse_response

def test_valid_response():
    valid_response = b"HTTP/1.1 200 OK\r\nDate: Fri, 30 Jan 2026 16:08:00 GMT\r\nContent-Type: text/html\r\nContent-Length: 44"
    expected_response = ('HTTP/1.1 200 OK', {'Date': 'Fri, 30 Jan 2026 16:08:00 GMT', 'Content-Type': 'text/html', 'Content-Length': '44'})
    assert parse_response(valid_response) == expected_response

def test_invalid_response():
    invalid_response_headers = b"HTTP/1.1 200 OK\r\nDate: Fri, 30 Jan 2026 16:08:00 GMT\r\nContent-Type text/html\r\nContent-Length: 44"
    with pytest.raises(ValueError):
        parse_response(invalid_response_headers)
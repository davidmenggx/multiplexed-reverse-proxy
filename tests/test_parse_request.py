import pytest

from utilities import parse_request

def test_valid_request():
    valid_request = b"POST /api/public_file.txt HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 73"
    expected_response = ('POST /api/public_file.txt HTTP/1.1', {'Host': 'api.example.com', 'Content-Type': 'application/json', 'Content-Length': '73'})
    assert parse_request(valid_request) == expected_response

def test_invalid_request_line():
    invalid_request_line = b"POST /api/public_file.txt\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 73"
    with pytest.raises(ValueError):
        parse_request(invalid_request_line)

def test_invalid_request_headers():
    invalid_request_headers = b"POST /api/public_file.txt HTTP/1.1\r\nHost: api.example.com\r\nContent-Type application/json\r\nContent-Length: 73"
    with pytest.raises(ValueError):
        parse_request(invalid_request_headers)
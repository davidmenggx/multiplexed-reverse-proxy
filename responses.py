from datetime import datetime, timezone

def _format_error_response(status_line: str) -> bytes:
    """Template for standard server responses (errors)"""
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    return (f"HTTP/1.1 {status_line}\r\nServer: David's server\r\nDate: {now}\r\nContent-Length: 0\r\n\r\n").encode('utf-8')

def bad_request(): return _format_error_response('400 Bad Request')

def header_too_large(): return _format_error_response('431 Request Header Fields Too Large')

def bad_gateway(): return _format_error_response('502 Bad Gateway')

def service_unavailable(): return _format_error_response('503 Service Unavailable')

def http_version_not_supported(): return _format_error_response('505 HTTP Version Not Supported')

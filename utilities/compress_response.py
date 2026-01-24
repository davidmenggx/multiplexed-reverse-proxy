import gzip

def compress_response(response_body: bytes) -> bytes:
    return gzip.compress(response_body)
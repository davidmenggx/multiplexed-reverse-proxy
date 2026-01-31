import gzip

def compress_response(response_body: bytes) -> bytes:
    """Returns gzipped response in bytes"""
    return gzip.compress(response_body)
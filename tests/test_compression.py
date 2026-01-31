import gzip

from utilities import compress_response

def test_compression():
    message = b'Hello World'
    
    compressed_message = compress_response(message)
    assert gzip.decompress(compressed_message) == message
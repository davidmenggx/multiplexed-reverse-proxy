from utilities import get_cache_control

def test_valid_cache_line_quotes():
    valid_request = 'must-revalidate, max-age="604800"'
    assert get_cache_control(valid_request) == 604800

def test_valid_cache_line_no_quotes():
    valid_request = 'must-revalidate, max-age=604800'
    assert get_cache_control(valid_request) == 604800

def test_nondescript_cache_line():
    nondescript_request = 'must-revalidate'
    assert get_cache_control(nondescript_request) == 0

def test_empty_cache_line():
    assert get_cache_control(' ') == 0
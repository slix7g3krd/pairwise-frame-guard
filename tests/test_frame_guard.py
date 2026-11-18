from security.frame_guard import (
    xfo_header,
    csp_frame_ancestors,
    is_framable,
    validate_frame_options
)


def test_deny():
    assert xfo_header('deny') == 'DENY'

def test_sameorigin():
    assert xfo_header('sameorigin') == 'SAMEORIGIN'

def test_csp_none():
    assert csp_frame_ancestors(None) == "frame-ancestors 'none'"

def test_csp_list():
    assert 'app.example' in csp_frame_ancestors({'app.example'})

def test_framable_deny():
    assert is_framable({'X-Frame-Options': 'DENY'}) is False

def test_framable_same():
    assert is_framable({'X-Frame-Options': 'SAMEORIGIN'}) is True

def test_invalid():
    assert validate_frame_options('ALLOW-FROM https://evil') is False

def test_conflict():
    assert is_framable({'X-Frame-Options': 'SAMEORIGIN', 'Content-Security-Policy': "frame-ancestors 'none'"}) is False

def test_empty():
    assert is_framable({}) is False

def test_case():
    assert validate_frame_options('deny') is True

def test_allow_from():
    assert xfo_header('allow-from') is None

def test_multiple():
    assert is_framable({'X-Frame-Options': 'ALLOWALL'}) is False

def test_no_header():
    assert xfo_header(None) == 'DENY'

def test_same_true():
    assert is_framable({'Content-Security-Policy': "frame-ancestors 'self'"}) is True

def test_error():
    assert is_framable({'X-Frame-Options': ''}) is False

"""Clickjacking protection helpers.

The module deliberately fails closed: whenever a value is missing, empty,
unrecognised, obsolete or ambiguous, the result denies framing instead of
falling back to "embeddable".

Design notes
------------
* ``X-Frame-Options`` and CSP ``frame-ancestors`` are evaluated together and
  the stricter result wins (a browser must satisfy both).
* ``ALLOW-FROM`` is obsolete and ignored by every current browser, so it is
  never accepted as protection.
* Duplicate headers (including differently cased keys and list values) are
  merged and evaluated individually; one rejecting value rejects the response.
* Allow-lists are fixed: wildcards, whitespace, separators and other
  injection vectors are rejected rather than interpolated into CSP.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    'xfo_header',
    'csp_frame_ancestors',
    'is_framable',
    'validate_frame_options',
]

_DENY = 'DENY'
_SAMEORIGIN = 'SAMEORIGIN'
_SUPPORTED_XFO = {_DENY: _DENY, _SAMEORIGIN: _SAMEORIGIN}

_XFO_HEADER = 'x-frame-options'
_CSP_HEADER = 'content-security-policy'
_CSP_NONE = "frame-ancestors 'none'"

# Exact CSP keyword tokens (already quoted) that are safe to emit.
_SAFE_KEYWORDS = frozenset({"'self'", "'none'"})

# A fixed allow-list entry: an optional scheme plus a host and optional port.
# Wildcards, separators, quotes and whitespace are rejected because they
# would widen the allow-list or break out of the directive.
_SAFE_SOURCE_RE = re.compile(
    r"^(?:(?:https?)://)?[A-Za-z0-9.-]+(?::[0-9]{1,5})?$"
)


def _text(value: Any) -> str:
    """Normalise a header value to stripped text (``None`` -> ``''``)."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('latin-1', 'replace').strip()
    return str(value).strip()


def xfo_header(value: Any = None) -> str | None:
    """Return a canonical, safe ``X-Frame-Options`` value.

    * ``None`` / empty / unknown values default to ``DENY`` so routes, error
      pages and login pages without explicit configuration stay protected.
    * ``ALLOW-FROM ...`` returns ``None``: modern browsers ignore the
      directive, so it must not be emitted as if it offered protection.
    * Matching is case-insensitive and surrounding whitespace is ignored.
    """
    text = _text(value)
    if not text:
        return _DENY

    normalized = text.upper()
    # Compare the first token so "allow-from https://example" is rejected
    # whether the URL is separated by a space or a tab.
    if normalized.split(None, 1)[0] == 'ALLOW-FROM':
        return None

    return _SUPPORTED_XFO.get(normalized, _DENY)


def validate_frame_options(value: Any) -> bool:
    """Return whether *value* is an X-Frame-Options value we accept.

    Only a bare ``DENY`` or ``SAMEORIGIN`` (any case) is valid.  Obsolete
    ``ALLOW-FROM`` values, ``ALLOWALL`` and empty values are rejected.
    """
    text = _text(value)
    if not text:
        return False
    return text.upper() in _SUPPORTED_XFO


def _source_is_unsafe(source: str) -> bool:
    """Reject anything outside a fixed host/keyword allow-list."""
    if not source:
        return True
    if source.lower() in _SAFE_KEYWORDS:
        return False
    return _SAFE_SOURCE_RE.fullmatch(source) is None


def csp_frame_ancestors(sources: Any = None) -> str:
    """Build a ``frame-ancestors`` directive from a fixed allow-list.

    ``None`` or an empty collection yields ``frame-ancestors 'none'``.  Any
    unsafe entry (wildcard, whitespace, comma, semicolon, quote, ...) makes
    the whole directive fall back to ``'none'`` instead of being interpolated
    into the header.  Output order is deterministic for sets and preserved
    for sequences.
    """
    if sources is None:
        return _CSP_NONE
    if isinstance(sources, (str, bytes)):
        iterable = [sources]
    elif isinstance(sources, (set, frozenset)):
        iterable = sorted(sources, key=lambda item: _text(item).lower())
    else:
        iterable = list(sources)

    cleaned: list[str] = []
    for source in iterable:
        text = _text(source)
        # Accept the common unquoted spelling of the keywords and emit them
        # in the quoted form CSP requires.
        if text.lower() in ('self', 'none'):
            text = text.lower().join(("'", "'"))
        if _source_is_unsafe(text):
            return _CSP_NONE
        if text not in cleaned:
            cleaned.append(text)

    if not cleaned:
        return _CSP_NONE
    return 'frame-ancestors ' + ' '.join(cleaned)


def _iter_header_values(raw: Any):
    """Flatten a header value that may be repeated (list/tuple/set)."""
    if isinstance(raw, (list, tuple, set, frozenset)):
        for item in raw:
            yield from _iter_header_values(item)
    else:
        yield raw


def _header_values(headers: Mapping[Any, Any], name: str) -> list[Any]:
    """Collect every value for *name*, matching keys case-insensitively."""
    if not headers:
        return []
    values: list[Any] = []
    for key, raw in headers.items():
        if _text(key).lower() == name:
            values.extend(_iter_header_values(raw))
    return values


def _xfo_allows(values: list[Any]) -> tuple[bool, bool]:
    """Return ``(allows_framing, has_effective_directive)`` for XFO values."""
    if not values:
        return True, False

    for value in values:
        # A single XFO field may contain a comma-separated list; that is
        # invalid but proxies sometimes merge duplicates this way.  Evaluate
        # every entry so the strictest one wins.
        for part in _text(value).split(','):
            part = part.strip()
            if not part:
                # Present but empty: no usable protection -> fail closed.
                return False, True
            normalized = xfo_header(part)
            if normalized is None or normalized == _DENY:
                return False, True
    return True, True


def _sources_allow(sources: list[str]) -> bool:
    """Evaluate parsed ``frame-ancestors`` source expressions.

    Only positively recognised sources count: the quoted ``'self'`` keyword or
    a host/scheme entry matching the fixed allow-list pattern.  Anything else
    (wildcards, unquoted/invalid keywords, unknown schemes, injection
    attempts) makes the decision fail closed.
    """
    if not sources:
        return False

    allowed = False
    for source in sources:
        lowered = source.lower()
        if lowered == "'none'" or '*' in source:
            # ``frame-ancestors *`` allows any site to frame us and must never
            # be treated as protection.
            return False
        if lowered == "'self'":
            allowed = True
            continue
        if lowered in ('self', 'none'):
            # Unquoted keywords are invalid CSP and match nothing.
            return False
        if _SAFE_SOURCE_RE.fullmatch(source) is None:
            return False
        allowed = True
    return allowed


def _csp_allows(values: list[Any]) -> tuple[bool, bool]:
    """Return ``(allows_framing, has_effective_directive)`` for CSP values.

    Multiple CSP headers (and comma-separated policies within one header) are
    enforced together: a request must satisfy every policy, so one denying
    policy denies the whole response.
    """
    has_directive = False
    if not values:
        return True, False

    for value in values:
        for policy in _text(value).split(','):
            for directive in policy.split(';'):
                directive = directive.strip()
                if not directive:
                    continue
                pieces = directive.split(None, 1)
                if pieces[0].lower() != 'frame-ancestors':
                    continue
                has_directive = True
                sources = pieces[1].split() if len(pieces) > 1 else []
                if not _sources_allow(sources):
                    return False, True
    return True, has_directive


def is_framable(headers: Mapping[Any, Any] | None = None) -> bool:
    """Decide whether a response may be embedded in a frame.

    Both header families are inspected.  ``X-Frame-Options`` and CSP
    ``frame-ancestors`` are combined with a logical AND (the stricter result
    wins).  Missing/empty headers, obsolete values, wildcard allow-lists and
    duplicates containing any rejecting value all result in ``False``.
    """
    if not headers:
        return False

    xfo_values = _header_values(headers, _XFO_HEADER)
    csp_values = _header_values(headers, _CSP_HEADER)

    xfo_allows, xfo_present = _xfo_allows(xfo_values)
    if not xfo_allows:
        return False

    csp_allows, csp_present = _csp_allows(csp_values)
    if not csp_allows:
        return False

    # Default deny: a response that carries neither an X-Frame-Options header
    # nor a frame-ancestors directive is embeddable, so treat it as unsafe.
    return bool(xfo_present or csp_present)

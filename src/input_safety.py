"""Small, explicit input bounds and lossless diagnostic text handling."""

import json

MAX_JSON_DEPTH = 64
MAX_INTEGER_DIGITS = 4300


def safe_text(value):
    """Render lone surrogates as visible \\u escapes; never drop their value."""
    return str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")


def has_surrogate(text):
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def bounded_json_loads(raw):
    """Reject deep containers before decoding, then validate all decoded text.

    The lexical depth scan honors quoted strings and escapes. json.loads remains
    responsible for syntax validation. Limits are local, never interpreter-wide.
    """
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} containers")
        elif char in "]}":
            depth -= 1

    def integer(text):
        if len(text.lstrip("-")) > MAX_INTEGER_DIGITS:
            raise ValueError(f"JSON integer exceeds {MAX_INTEGER_DIGITS} digits")
        return int(text)

    def constant(text):
        raise ValueError(f"Non-finite JSON number: {text}")

    value = json.loads(raw, parse_int=integer, parse_constant=constant)
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and has_surrogate(item):
            raise ValueError("Malformed Unicode: lone surrogate; original input retained as escaped text")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value

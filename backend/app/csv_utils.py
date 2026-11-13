"""CSV cell helpers for safe spreadsheet consumption."""


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def spreadsheet_safe(value):
    """Prefix formula-like text so spreadsheet programs treat it as data."""
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n").startswith(_FORMULA_PREFIXES):
        return "'" + value
    if value.startswith(("\t", "\r")):
        return "'" + value
    return value

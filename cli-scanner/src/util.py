import re


def parse_time_threshold(time_str):
    """
    Convert a string like '24h', '7d', '30m' into seconds.
    Supported suffixes: s (seconds), m (minutes), h (hours), d (days)
    """
    pattern = r"^(\d+)([smhd])$"
    match = re.match(pattern, time_str.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid time format: {time_str}. Use formats like '30m', '24h', '7d'."
        )

    value, unit = match.groups()
    value = int(value)

    multiplier = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }

    return value * multiplier[unit]

def retry_delay_seconds(attempt: int, *, base_seconds: int = 30, maximum_seconds: int = 900) -> int:
    normalized = max(1, attempt)
    return min(maximum_seconds, base_seconds * (2 ** (normalized - 1)))

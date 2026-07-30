from typing import TypeVar


T = TypeVar("T")
_brand_cursor = 0


def select_brand_batch_at_cursor(brands: list[T], batch_size: int, cursor: int) -> tuple[list[T], int]:
    """Select a deterministic batch whose cursor can be stored durably."""
    if not brands or batch_size <= 0:
        return [], 0
    size = min(batch_size, len(brands))
    start = cursor % len(brands)
    selected = [brands[(start + offset) % len(brands)] for offset in range(size)]
    return selected, (start + size) % len(brands)


def select_brand_batch(brands: list[T], batch_size: int) -> list[T]:
    global _brand_cursor
    selected, _brand_cursor = select_brand_batch_at_cursor(brands, batch_size, _brand_cursor)
    return selected

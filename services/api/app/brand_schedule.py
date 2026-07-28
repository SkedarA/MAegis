from typing import TypeVar


T = TypeVar("T")
_brand_cursor = 0


def select_brand_batch(brands: list[T], batch_size: int) -> list[T]:
    global _brand_cursor
    if not brands or batch_size <= 0:
        return []
    size = min(batch_size, len(brands))
    selected = [brands[(_brand_cursor + offset) % len(brands)] for offset in range(size)]
    _brand_cursor = (_brand_cursor + size) % len(brands)
    return selected

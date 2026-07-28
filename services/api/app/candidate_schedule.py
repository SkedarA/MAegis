from typing import TypeVar


T = TypeVar("T")


def rotating_batch(items: list[T], cursor: int, batch_size: int) -> tuple[list[T], int]:
    if not items or batch_size <= 0:
        return [], 0
    start = cursor % len(items)
    size = min(batch_size, len(items))
    selected = [items[(start + offset) % len(items)] for offset in range(size)]
    return selected, (start + size) % len(items)


def brand_checkpoint(checkpoint: dict, brand_id: str) -> dict:
    return dict((checkpoint.get("brands") or {}).get(brand_id) or {})


def with_brand_checkpoint(checkpoint: dict, brand_id: str, value: dict) -> dict:
    updated = dict(checkpoint)
    brands = dict(updated.get("brands") or {})
    brands[brand_id] = value
    updated["brands"] = brands
    return updated

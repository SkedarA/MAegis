from typing import TypeVar


T = TypeVar("T")


def rotating_batch(items: list[T], cursor: int, batch_size: int) -> tuple[list[T], int]:
    if not items or batch_size <= 0:
        return [], 0
    start = cursor % len(items)
    size = min(batch_size, len(items))
    selected = [items[(start + offset) % len(items)] for offset in range(size)]
    return selected, (start + size) % len(items)


def prioritized_rotating_batch(
    items: list[T],
    cursor: int,
    priority_cursor: int,
    batch_size: int,
    is_priority,
    priority_fraction: float = 0.35,
) -> tuple[list[T], int, int]:
    """Reserve part of every bounded sweep for high-yield candidates."""
    if not items or batch_size <= 0:
        return [], 0, 0
    priority = [item for item in items if is_priority(item)]
    background = [item for item in items if not is_priority(item)]
    if not priority:
        batch, next_cursor = rotating_batch(background, cursor, batch_size)
        return batch, next_cursor, 0
    if not background:
        batch, next_priority_cursor = rotating_batch(priority, priority_cursor, batch_size)
        return batch, 0, next_priority_cursor
    priority_size = max(1, round(batch_size * max(0.0, min(priority_fraction, 1.0))))
    if batch_size > 1:
        priority_size = min(priority_size, batch_size - 1)
    priority_batch, next_priority_cursor = rotating_batch(priority, priority_cursor, priority_size)
    background_batch, next_cursor = rotating_batch(background, cursor, batch_size - len(priority_batch))
    return priority_batch + background_batch, next_cursor, next_priority_cursor


async def fetch_candidate_batch(connector, items: list[T]) -> tuple[list[tuple[T, object]], list[str]]:
    """Fetch every candidate even when an individual external lookup fails."""
    collected: list[tuple[T, object]] = []
    failures: list[str] = []
    for item in items:
        try:
            observations, _ = await connector.fetch(item.domain, {})
        except Exception as exc:
            failures.append(f"{item.domain}: {type(exc).__name__}: {exc}"[:300])
            continue
        collected.extend((item, observation) for observation in observations)
    return collected, failures


def brand_checkpoint(checkpoint: dict, brand_id: str) -> dict:
    return dict((checkpoint.get("brands") or {}).get(brand_id) or {})


def with_brand_checkpoint(checkpoint: dict, brand_id: str, value: dict) -> dict:
    updated = dict(checkpoint)
    brands = dict(updated.get("brands") or {})
    brands[brand_id] = value
    updated["brands"] = brands
    return updated

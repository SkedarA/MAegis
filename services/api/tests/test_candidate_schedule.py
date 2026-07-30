import unittest

from app.candidate_schedule import brand_checkpoint, prioritized_rotating_batch, rotating_batch, with_brand_checkpoint


class CandidateScheduleTests(unittest.TestCase):
    def test_rotation_eventually_visits_the_entire_pool(self):
        values = list(range(9))
        cursor = 0
        visited: list[int] = []
        for _ in range(3):
            batch, cursor = rotating_batch(values, cursor, 3)
            visited.extend(batch)
        self.assertEqual(visited, values)
        self.assertEqual(cursor, 0)

    def test_rotation_wraps_without_duplicates_inside_batch(self):
        batch, cursor = rotating_batch(["a", "b", "c", "d"], 3, 3)
        self.assertEqual(batch, ["d", "a", "b"])
        self.assertEqual(cursor, 2)

    def test_checkpoints_are_isolated_per_brand(self):
        checkpoint = with_brand_checkpoint({}, "brand-a", {"cursor": 4})
        checkpoint = with_brand_checkpoint(checkpoint, "brand-b", {"cursor": 8})
        self.assertEqual(brand_checkpoint(checkpoint, "brand-a"), {"cursor": 4})
        self.assertEqual(brand_checkpoint(checkpoint, "brand-b"), {"cursor": 8})

    def test_priority_lane_and_background_both_advance(self):
        values = ["priority-a", "priority-b", "priority-c", "background-a", "background-b", "background-c", "background-d"]
        first, cursor, priority_cursor = prioritized_rotating_batch(values, 0, 0, 4, lambda value: value.startswith("priority"), 0.5)
        second, next_cursor, next_priority_cursor = prioritized_rotating_batch(values, cursor, priority_cursor, 4, lambda value: value.startswith("priority"), 0.5)
        self.assertEqual(first, ["priority-a", "priority-b", "background-a", "background-b"])
        self.assertEqual(second, ["priority-c", "priority-a", "background-c", "background-d"])
        self.assertEqual(next_cursor, 0)
        self.assertEqual(next_priority_cursor, 1)

    def test_priority_lane_falls_back_when_no_priority_items_exist(self):
        batch, cursor, priority_cursor = prioritized_rotating_batch([1, 2, 3], 0, 0, 2, lambda _: False)
        self.assertEqual(batch, [1, 2])
        self.assertEqual(cursor, 2)
        self.assertEqual(priority_cursor, 0)


if __name__ == "__main__":
    unittest.main()

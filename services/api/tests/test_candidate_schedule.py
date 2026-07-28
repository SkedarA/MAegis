import unittest

from app.candidate_schedule import brand_checkpoint, rotating_batch, with_brand_checkpoint


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


if __name__ == "__main__":
    unittest.main()

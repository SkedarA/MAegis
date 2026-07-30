import re
import unittest

from app.brand_catalog import ROMANIAN_BRAND_CATALOG, get_catalog
from app.brand_schedule import select_brand_batch, select_brand_batch_at_cursor


DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class BrandCatalogTests(unittest.TestCase):
    def test_catalog_is_operationally_bounded_and_unique(self):
        self.assertGreaterEqual(len(ROMANIAN_BRAND_CATALOG), 20)
        self.assertLessEqual(len(ROMANIAN_BRAND_CATALOG), 50)
        self.assertEqual(len({item.key for item in ROMANIAN_BRAND_CATALOG}), len(ROMANIAN_BRAND_CATALOG))
        self.assertEqual(len({item.name.casefold() for item in ROMANIAN_BRAND_CATALOG}), len(ROMANIAN_BRAND_CATALOG))

    def test_catalog_official_domains_are_normalized(self):
        domains = [domain for item in ROMANIAN_BRAND_CATALOG for domain in item.official_domains]
        self.assertTrue(all(DOMAIN_RE.fullmatch(domain) for domain in domains))
        self.assertEqual(len(domains), len(set(domains)))

    def test_catalog_contains_priority_romanian_brands(self):
        selected = get_catalog(["dacia", "uipath", "bitdefender", "banca-transilvania"])
        self.assertEqual([item.key for item in selected], ["dacia", "uipath", "bitdefender", "banca-transilvania"])

    def test_brand_batch_rotates_without_exceeding_budget(self):
        brands = list(ROMANIAN_BRAND_CATALOG[:7])
        first = select_brand_batch(brands, 3)
        second = select_brand_batch(brands, 3)
        self.assertEqual(len(first), 3)
        self.assertEqual(len(second), 3)
        self.assertTrue(set(first).isdisjoint(second))

    def test_durable_brand_cursor_resumes_after_restart(self):
        brands = list(ROMANIAN_BRAND_CATALOG[:7])
        first, cursor = select_brand_batch_at_cursor(brands, 3, 0)
        resumed, next_cursor = select_brand_batch_at_cursor(brands, 3, cursor)
        self.assertEqual(first, brands[:3])
        self.assertEqual(resumed, brands[3:6])
        self.assertEqual(next_cursor, 6)


if __name__ == "__main__":
    unittest.main()

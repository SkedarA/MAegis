import unittest

from app.domain_context import build_domain_context, registrable_domain


class DomainContextTests(unittest.TestCase):
    def test_platform_tenant_suppresses_registry_age(self):
        context = build_domain_context("brand-login.pages.dev", [])
        self.assertEqual(context["domain_type"], "platform_tenant")
        self.assertEqual(context["hosting_provider"]["name"], "Cloudflare Pages")
        self.assertFalse(context["registration_relevant"])
        self.assertIsNone(context["registration_date"])

    def test_registered_domain_keeps_compound_suffix(self):
        self.assertEqual(registrable_domain("login.brand.com.ro"), "brand.com.ro")

    def test_registrar_contact_is_read_from_rdap_vcard(self):
        evidence = [{"evidence_type": "rdap", "payload": {"events": [], "raw": {"entities": [{"roles": ["registrar"], "handle": "REG", "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"], ["email", {}, "text", "abuse@example.test"]]]}]}}}]
        context = build_domain_context("brand-login.example", evidence)
        self.assertEqual(context["registrar"], {"name": "Example Registrar", "contact": "abuse@example.test"})


if __name__ == "__main__":
    unittest.main()

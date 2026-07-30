import unittest
from pydantic import ValidationError

from app.domain_context import build_domain_context, registrable_domain
from app.schemas import DomainContextOverrideUpdate


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
        self.assertEqual(context["registrar"]["name"], "Example Registrar")
        self.assertEqual(context["registrar"]["contact"], "abuse@example.test")
        self.assertEqual(context["registrar"]["source"], "rdap")

    def test_nested_rdap_abuse_contact_is_preferred(self):
        registrar = {
            "roles": ["registrar"],
            "handle": "REG-1",
            "vcardArray": ["vcard", [["org", {}, "text", "Registrar Group"]]],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.test"]]]}],
        }
        context = build_domain_context("brand-login.example", [{"evidence_type": "rdap", "payload": {"events": [], "raw": {"entities": [registrar]}}}])
        self.assertEqual(context["registrar"]["name"], "Registrar Group")
        self.assertEqual(context["registrar"]["contact"], "abuse@registrar.test")

    def test_cname_identifies_hosting_provider_with_high_confidence(self):
        evidence = [{"evidence_type": "dns", "payload": {"records": {"CNAME": ["target.vercel-dns.com"], "NS": []}}}]
        context = build_domain_context("brand-login.example", evidence)
        self.assertEqual(context["hosting_provider"]["name"], "Vercel")
        self.assertEqual(context["hosting_provider"]["source"], "dns_cname")
        self.assertEqual(context["hosting_provider"]["confidence"], "high")

    def test_urlscan_network_is_used_when_dns_has_no_provider(self):
        evidence = [{"evidence_type": "source_observation", "payload": {"page_asnname": "CLOUDFLARENET"}}]
        context = build_domain_context("brand-login.example", evidence)
        self.assertEqual(context["hosting_provider"]["name"], "Cloudflare")
        self.assertEqual(context["hosting_provider"]["source"], "urlscan_network")

    def test_analyst_override_preserves_provenance(self):
        override = {"hosting_provider_name": "Verified Host", "hosting_provider_contact": "abuse@host.test", "registrar_name": "Verified Registrar", "registrar_contact": "abuse@registrar.test", "rationale": "Confirmed in provider response", "updated_by": "Case Analyst", "updated_at": "2026-07-30T08:00:00+00:00"}
        context = build_domain_context("brand-login.example", [], override)
        self.assertEqual(context["hosting_provider"]["source"], "analyst_override")
        self.assertEqual(context["registrar"]["name"], "Verified Registrar")
        self.assertTrue(context["override"]["active"])

    def test_manual_contacts_reject_unsafe_protocols(self):
        with self.assertRaises(ValidationError):
            DomainContextOverrideUpdate(hosting_provider_name="Host", hosting_provider_contact="javascript:alert(1)", rationale="Unsafe value test")
        valid = DomainContextOverrideUpdate(hosting_provider_name="Host", hosting_provider_contact="abuse@host.test", rationale="Verified contact")
        self.assertEqual(valid.hosting_provider_contact, "abuse@host.test")


if __name__ == "__main__":
    unittest.main()

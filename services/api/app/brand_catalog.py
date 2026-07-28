from dataclasses import dataclass


DEFAULT_ABUSE_KEYWORDS = (
    "account",
    "auth",
    "invoice",
    "login",
    "payment",
    "secure",
    "security",
    "support",
    "verify",
)


@dataclass(frozen=True)
class CatalogBrand:
    key: str
    name: str
    sector: str
    official_domains: tuple[str, ...]
    trademarks: tuple[str, ...]
    permitted_variations: tuple[str, ...] = ()
    keywords: tuple[str, ...] = DEFAULT_ABUSE_KEYWORDS


# Curated from public company and BVB sources. Domains are allowlisted official
# assets, not suspected infrastructure. Keep this list small enough for a solo
# deployment and review it before each published research run.
ROMANIAN_BRAND_CATALOG: tuple[CatalogBrand, ...] = (
    CatalogBrand("dacia", "Dacia", "automotive", ("dacia.ro", "dacia.com"), ("Dacia", "Automobile Dacia")),
    CatalogBrand("uipath", "UiPath", "technology", ("uipath.com",), ("UiPath",)),
    CatalogBrand("bitdefender", "Bitdefender", "cybersecurity", ("bitdefender.com",), ("Bitdefender",)),
    CatalogBrand("emag", "eMAG", "e-commerce", ("emag.ro",), ("eMAG", "Dante International")),
    CatalogBrand("banca-transilvania", "Banca Transilvania", "banking", ("bancatransilvania.ro",), ("Banca Transilvania", "BT"), ("BT Pay",)),
    CatalogBrand("omv-petrom", "OMV Petrom", "energy", ("omvpetrom.com",), ("OMV Petrom", "Petrom")),
    CatalogBrand("hidroelectrica", "Hidroelectrica", "energy", ("hidroelectrica.ro",), ("Hidroelectrica",)),
    CatalogBrand("romgaz", "Romgaz", "energy", ("romgaz.ro",), ("Romgaz", "SNG")),
    CatalogBrand("nuclearelectrica", "Nuclearelectrica", "energy", ("nuclearelectrica.ro",), ("Nuclearelectrica", "SNN")),
    CatalogBrand("transgaz", "Transgaz", "energy", ("transgaz.ro",), ("Transgaz", "SNTGN Transgaz")),
    CatalogBrand("electrica", "Electrica", "energy", ("electrica.ro",), ("Electrica", "Grupul Electrica")),
    CatalogBrand("digi", "DIGI", "telecommunications", ("digi.ro", "digi-communications.ro"), ("DIGI", "Digi Communications", "RCS & RDS")),
    CatalogBrand("dedeman", "Dedeman", "retail", ("dedeman.ro",), ("Dedeman",)),
    CatalogBrand("altex", "Altex", "retail", ("altex.ro",), ("Altex", "Altex Romania")),
    CatalogBrand("fan-courier", "FAN Courier", "logistics", ("fancourier.ro",), ("FAN Courier", "FAN")),
    CatalogBrand("sameday", "Sameday", "logistics", ("sameday.ro",), ("Sameday", "Delivery Solutions"), ("easybox",)),
    CatalogBrand("tarom", "TAROM", "aviation", ("tarom.ro",), ("TAROM", "Romanian Air Transport")),
    CatalogBrand("medlife", "MedLife", "healthcare", ("medlife.ro",), ("MedLife",)),
    CatalogBrand("regina-maria", "Regina Maria", "healthcare", ("reginamaria.ro",), ("Regina Maria", "Reteaua de Sanatate Regina Maria")),
    CatalogBrand("one-united", "One United Properties", "real-estate", ("one.ro",), ("One United Properties", "ONE")),
    CatalogBrand("teraplast", "TeraPlast", "manufacturing", ("teraplast.ro",), ("TeraPlast", "TeraPlast Group")),
    CatalogBrand("arobs", "AROBS", "technology", ("arobs.com", "arobsgrup.ro"), ("AROBS", "AROBS Transilvania Software")),
    CatalogBrand("autonom", "Autonom", "mobility", ("autonom.ro",), ("Autonom", "Autonom Services")),
    CatalogBrand("farmec", "Farmec", "consumer-goods", ("farmec.ro",), ("Farmec", "Gerovital")),
    CatalogBrand("aquila", "Aquila", "distribution", ("aquila.ro",), ("Aquila", "Aquila Part Prod Com")),
    CatalogBrand("bittnet", "Bittnet", "technology", ("bittnet.ro",), ("Bittnet", "Bittnet Group")),
    CatalogBrand("sphera", "Sphera Franchise Group", "food-service", ("spheragroup.com",), ("Sphera Franchise Group", "Sphera")),
    CatalogBrand("romstal", "Romstal", "retail", ("romstal.ro",), ("Romstal",)),
    CatalogBrand("mobexpert", "Mobexpert", "retail", ("mobexpert.ro",), ("Mobexpert",)),
    CatalogBrand("brd", "BRD Groupe Societe Generale", "banking", ("brd.ro",), ("BRD", "BRD Groupe Societe Generale")),
    CatalogBrand("cec-bank", "CEC Bank", "banking", ("cec.ro",), ("CEC Bank", "CEC")),
    CatalogBrand("antibiotice-iasi", "Antibiotice Iasi", "pharmaceuticals", ("antibiotice.ro",), ("Antibiotice Iasi", "Antibiotice")),
)


CATALOG_BY_KEY = {brand.key: brand for brand in ROMANIAN_BRAND_CATALOG}


def get_catalog(keys: list[str] | None = None) -> list[CatalogBrand]:
    if keys is None:
        return list(ROMANIAN_BRAND_CATALOG)
    unknown = sorted(set(keys) - CATALOG_BY_KEY.keys())
    if unknown:
        raise ValueError(f"Unknown catalog keys: {', '.join(unknown)}")
    requested = set(keys)
    return [brand for brand in ROMANIAN_BRAND_CATALOG if brand.key in requested]

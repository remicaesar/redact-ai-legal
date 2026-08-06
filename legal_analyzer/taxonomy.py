"""Classification and privacy vocabulary for legal document review."""

from __future__ import annotations

import json
import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

SUPPORTED_EXTENSIONS = {".docx", ".doc", ".pdf", ".xlsx", ".pptx", ".zip", ".png", ".jpg", ".jpeg", ".udf", ".txt", ".md"}
IGNORE_PATTERNS = {".DS_Store", "~$", ".gitignore", ".git"}

TERMINOLOGY = {
    "redaction": {
        "label": "Redaction",
        "description": "Removing or masking information from a document.",
    },
    "pseudonymization": {
        "label": "Pseudonymization",
        "description": "Replacing identifiers with consistent placeholders while a mapping may exist.",
    },
    "de_identification": {
        "label": "De-identification",
        "description": "Reducing identifiability without necessarily eliminating all re-identification risk.",
    },
    "anonymization": {
        "label": "Anonymization",
        "description": "Irreversible transformation where the data subject is no longer reasonably identifiable.",
    },
}

OUTPUT_POSITIONING = (
    "Outputs are privacy-reviewed, risk-reduced legal documents. They should not be described as fully "
    "anonymous unless residual re-identification risk has been assessed and is genuinely low."
)

CATEGORIES = [
    ("corporate_law", "Sirketler Hukuku", "CORP"),
    ("contract_law", "Sozlesme Hukuku", "CONT"),
    ("intellectual_property", "Fikri Mulkiyet Hukuku", "IP"),
    ("data_privacy", "Kisisel Veriler (KVKK/GDPR)", "PRIV"),
    ("regulatory_compliance", "Duzenleyici/Uyumluluk", "REG"),
    ("labor_law", "Is Hukuku", "LAB"),
    ("litigation", "Uyusmazlik ve Dava", "LIT"),
    ("reports_presentations", "Raporlar ve Sunumlar", "REP"),
    ("other", "Diger", "DOC"),
]

SUBCATEGORIES = {
    "corporate_law": [
        ("shareholders_agreement", "Hissedar Sozlesmeleri (SHA)"),
        ("stock_purchase", "Hisse Devir/Bagis Sozlesmeleri (SPA)"),
        ("post_incorporation", "Kurulus Sonrasi Evraklar"),
        ("board_resolutions", "Yonetim Kurulu Kararlari"),
        ("capital_increase", "Sermaye Artirimi"),
        ("bylaws", "Sirket Ana Sozlesmesi/Tuzuk"),
        ("power_of_attorney", "Vekaletname"),
    ],
    "contract_law": [
        ("consulting_advisory", "Danismanlik Sozlesmeleri"),
        ("employment", "Is Sozlesmeleri"),
        ("service_agreement", "Hizmet Sozlesmeleri"),
        ("cooperation_protocol", "Isbirligi Protokolleri"),
        ("saas_software", "SaaS/Yazilim Sozlesmeleri"),
        ("sales_agreement", "Satis Sozlesmeleri"),
        ("management_agreement", "Yonetim Sozlesmeleri"),
    ],
    "intellectual_property": [
        ("ip_assignment", "IP Devir/Lisans"),
        ("trademark", "Marka Hukuku"),
        ("nda", "Gizlilik Sozlesmeleri (NDA)"),
    ],
    "data_privacy": [
        ("privacy_notice", "Aydinlatma Metinleri"),
        ("data_transfer", "Veri Aktarim Sozlesmeleri"),
        ("privacy_policy", "Gizlilik Politikalari"),
        ("cookie_policy", "Cerez Politikalari"),
        ("kvkk_compliance", "KVKK Uyumluluk"),
    ],
    "regulatory_compliance": [
        ("crypto_token", "Kripto/Token Raporlari"),
        ("legal_opinion", "Yasal Gorusler"),
        ("terms_of_use", "Kullanim Kosullari"),
        ("regulatory_report", "Duzenleyici Raporlar"),
    ],
    "labor_law": [
        ("discipline", "Disiplin/Ic Yonetmelik"),
        ("non_compete", "Rekabet Yasagi"),
        ("sweat_equity", "Sweat Equity/Phantom Stock"),
        ("compensation", "Prim/Maas/Haciz"),
        ("termination", "Fesih/Ihtar"),
    ],
    "litigation": [
        ("criminal_complaint", "Ceza Sikayeti/Suc Duyurusu"),
        ("petition", "Dilekce"),
        ("court_decision", "Mahkeme/Kurul Karari"),
        ("evidence", "Delil ve Ekler"),
    ],
    "reports_presentations": [
        ("due_diligence", "Durum Tespiti Raporlari"),
        ("meeting_minutes", "Toplanti Tutanaklari"),
        ("research", "Arastirma Raporlari"),
        ("presentation", "Sunumlar"),
        ("internal_docs", "Ic Evraklar"),
    ],
    "other": [
        ("asset_inventory", "Zimmet/Envanter"),
        ("settlement", "Sulh/Uzlasma"),
        ("safe_agreement", "SAFE Sozlesmeleri"),
        ("indemnity", "Tazminat/Sorumluluk"),
        ("miscellaneous", "Cesitli"),
    ],
}

CLASSIFICATION_RULES = [
    (["sikayet", "şikayet", "suc duyurusu", "suç duyurusu", "savciligi", "savcılığı", "supheli", "şüpheli"], "litigation", "criminal_complaint", ["ceza", "şikayet"]),
    (["dilekce", "dilekçe", "mahkemesi", "court", "petition"], "litigation", "petition", ["dilekçe"]),
    (["karar", "decision", "judgment"], "litigation", "court_decision", ["karar"]),
    (["delil", "evidence", "ek-"], "litigation", "evidence", ["delil"]),
    (["sha", "hissedarlar", "shareholders agreement"], "corporate_law", "shareholders_agreement", ["SHA", "hissedar"]),
    (["spa", "hisse devir", "hisse_devir", "stock purchase", "pay devir"], "corporate_law", "stock_purchase", ["SPA", "hisse devir"]),
    (["post-inc", "post incorporation", "bylaws", "initial-action", "coi"], "corporate_law", "post_incorporation", ["kuruluş", "post-inc"]),
    (["ykk", "yonetim kurulu", "yönetim kurulu", "board resolution", "bod consent"], "corporate_law", "board_resolutions", ["YKK"]),
    (["sermaye", "capital increase", "_gk_", "gk_"], "corporate_law", "capital_increase", ["sermaye"]),
    (["poa", "power of attorney", "vekaletname"], "corporate_law", "power_of_attorney", ["vekaletname"]),
    (["consulting agreement", "danismanlik", "danışmanlık", "advisory agreement", "advisor"], "contract_law", "consulting_advisory", ["danışmanlık"]),
    (["employment", "is sozlesmesi", "iş sözleşmesi", "contractor agreement"], "contract_law", "employment", ["iş sözleşmesi"]),
    (["hizmet", "service agreement", "saas agreement", "agent solution"], "contract_law", "service_agreement", ["hizmet"]),
    (["protokol", "isbirligi", "işbirliği", "cooperation"], "contract_law", "cooperation_protocol", ["protokol"]),
    (["software agreement", "yazilim", "yazılım"], "contract_law", "saas_software", ["yazılım"]),
    (["mesafeli satis", "mesafeli satış", "rspa"], "contract_law", "sales_agreement", ["satış"]),
    (["ip devir", "ip_assignment", "fikri mulkiyet", "fikri mülkiyet"], "intellectual_property", "ip_assignment", ["IP"]),
    (["nda", "gizlilik", "non-disclosure", "non disclosure"], "intellectual_property", "nda", ["NDA", "gizlilik"]),
    (["marka", "trademark"], "intellectual_property", "trademark", ["marka"]),
    (["aydinlatma", "aydınlatma", "privacy notice"], "data_privacy", "privacy_notice", ["KVKK"]),
    (["kvkk", "kisisel veri", "kişisel veri", "gdpr", "standart sozlesme", "scc"], "data_privacy", "kvkk_compliance", ["KVKK/GDPR"]),
    (["veri transfer", "data transfer", "dpa", "data processing"], "data_privacy", "data_transfer", ["veri aktarım"]),
    (["privacy policy", "gizlilik politikasi", "gizlilik politikası"], "data_privacy", "privacy_policy", ["gizlilik politikası"]),
    (["cookie", "cerez", "çerez"], "data_privacy", "cookie_policy", ["çerez"]),
    (["token", "mica", "kripto", "masak", "kvhs"], "regulatory_compliance", "crypto_token", ["kripto"]),
    (["legal opinion", "yasal gorus", "yasal görüş"], "regulatory_compliance", "legal_opinion", ["yasal görüş"]),
    (["terms of use", "terms of service", "kullanim kosullari", "kullanım koşulları"], "regulatory_compliance", "terms_of_use", ["kullanım koşulları"]),
    (["disiplin", "etik hat"], "labor_law", "discipline", ["disiplin"]),
    (["non compete", "non-compete", "non solicitation", "rekabet yasagi"], "labor_law", "non_compete", ["rekabet yasağı"]),
    (["sweat equity", "phantom stock"], "labor_law", "sweat_equity", ["sweat equity"]),
    (["prim", "maas haczi", "maaş haczi", "maas", "maaş"], "labor_law", "compensation", ["maaş"]),
    (["fesih", "termination", "ihtar"], "labor_law", "termination", ["fesih"]),
    (["durum tespit", "due diligence"], "reports_presentations", "due_diligence", ["durum tespiti"]),
    (["toplanti tutanagi", "toplantı tutanağı", "meeting minutes"], "reports_presentations", "meeting_minutes", ["toplantı"]),
    (["arastirma", "araştırma", "research"], "reports_presentations", "research", ["araştırma"]),
    (["presentation", "sunum"], "reports_presentations", "presentation", ["sunum"]),
    (["rapor", "report", "bilgi notu"], "reports_presentations", "research", ["rapor"]),
    (["safe"], "other", "safe_agreement", ["SAFE"]),
    (["zimmet"], "other", "asset_inventory", ["zimmet"]),
    (["sulh", "settlement"], "other", "settlement", ["sulh"]),
    (["indemnity", "tazminat"], "other", "indemnity", ["tazminat"]),
]

# Client roster used to seed the `clients` table (db/init_db.py). At runtime
# `detect_client()` reads the table, not this list.
#
# A real roster is client-confidential: committing it to a public repository
# discloses who the practice acts for. It therefore lives in a gitignored local
# file and is NEVER hardcoded here. `config/clients.example.json` documents the
# format with fictional entries.
CLIENTS_FILE = Path(
    os.environ.get("LEGAL_ANALYZER_CLIENTS_FILE", PROJECT_DIR / "config" / "clients.local.json")
)


def load_known_clients(path: Path | None = None) -> list[tuple[str, list[str]]]:
    """Load (name, aliases) pairs from local config; empty when absent.

    Returning empty is the safe default: seeding simply adds no clients, and
    documents are indexed without a client attribution rather than the tool
    failing or falling back to someone else's roster.
    """
    source = Path(path) if path else CLIENTS_FILE
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read client roster at {source}: {exc}") from exc

    entries = raw.get("clients", raw) if isinstance(raw, dict) else raw
    clients: list[tuple[str, list[str]]] = []
    for entry in entries:
        if isinstance(entry, dict):
            name, aliases = entry.get("name"), entry.get("aliases", [])
        else:
            name, aliases = entry[0], entry[1]
        if name:
            clients.append((str(name), [str(alias) for alias in aliases]))
    return clients


KNOWN_CLIENTS = load_known_clients()

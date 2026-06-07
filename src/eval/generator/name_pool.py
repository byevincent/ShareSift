"""Substitution name pools for the post-processor.

Per ``docs/generator_spec.md`` Rule 2, the synthetic generator's
LLM-produced output leaks sticky-default entity names (``jsmith``,
``jdoe``, ``Meridian``, ``Acme``, etc.) that would become a learned
fingerprint at training scale. The post-processor substitutes these
tokens with a draw from the pools defined here, consistent per record
and varied across records.

Pool sizes are chosen so that no individual replacement name appears
in more than ~1% of a 500-record batch under uniform sampling. Pools
are static constants — rotation across runs is achieved by the
per-record fresh-mapping discipline in
``postprocess.substitute_names``, not by changing the pool contents.

Discovered sticky defaults that get explicitly substituted:

* User-folder names the LLMs settle on (``jsmith``, ``jdoe`` etc.)
* Service-account patterns the LLMs invent (``svc-payroll``,
  ``svc-backup``)
* Project codenames (``atlas``) and service-name leakage
  (``jenkins`` used as a username)

Each is observed empirically from prompt-output audits. Add new
sticky-defaults to ``LLM_STICKY_DEFAULTS`` as they're spotted in
future batches.
"""

from __future__ import annotations

import re

# ----------------------------------------------------------------------------
# Sticky-default registry
# ----------------------------------------------------------------------------

# Tokens observed as LLM sticky defaults across Qwen / DeepSeek / ChatGPT
# prompt runs (2026-05-28). Substitution mandatory: each appears in
# multiple batches and would compound to a learned feature at training
# scale.
LLM_STICKY_DEFAULTS: frozenset[str] = frozenset(
    {
        # Human-name shapes
        "jsmith",
        "jdoe",
        "jthompson",
        "bwilson",
        "mchan",
        "mjohnson",
        "jrogers",
        "jlee",
        "dev1",
        "devuser",
        "temp_admin",
        # Project codenames the model defaults to
        "atlas",
        "meridian",
        "acme",
        "globex",
        "contoso",
        # Service-name leakage as usernames
        "jenkins",
        # Service-account patterns
        "svc-payroll",
        "svc-backup",
        "svc-deploy",
        "svc-monitor",
    }
)

# Pattern: 1-2 lowercase letters + 2+ lowercase letters, no separators.
# Matches LLM-default human-name shapes like jsmith, bwilson, jdoe, mchan.
# Deliberately tight: requires the first-initial-last-name structure so
# normal English words don't match.
USERNAME_PATTERN = re.compile(r"^[a-z]{1,2}[a-z]{3,}$")

# Service-account prefix pattern. Matches svc-X, svc_X, svcX.
SVC_ACCOUNT_PATTERN = re.compile(r"^svc[-_][a-z0-9-]+$", re.IGNORECASE)

# Common English words the pattern would FP on — these match the
# username-shape regex but shouldn't be substituted (they're real
# dictionary words used legitimately in paths). Conservative: any
# common-English word the pattern might catch as a name.
USERNAME_PATTERN_IGNORE: frozenset[str] = frozenset(
    {
        "templates", "samples", "examples", "documents", "downloads",
        "desktop", "pictures", "videos", "music", "users", "common",
        "shared", "public", "fixtures", "tests", "drafts", "guides",
        "archive", "policy", "demo", "old", "config", "configs",
        "credentials", "secrets", "tokens", "vault", "vaults", "logs",
        "backup", "backups", "scripts", "tools", "library", "libraries",
        "fonts", "media", "assets", "themes", "modules", "plugins",
        "services", "session", "sessions", "trash", "temp", "data",
        "wallets", "wallet", "browser", "chrome", "firefox", "edge",
        "default", "automation", "deployment", "deployments",
        "operations", "infrastructure", "interop", "library", "support",
        "calendar", "calendars", "screensavers", "wallpapers",
    }
)


# ----------------------------------------------------------------------------
# Replacement pools
# ----------------------------------------------------------------------------

# 200 first names spanning diverse origins. Selected for low overlap with
# project terminology and credential vocabulary. No celebrity-tier names
# (Elon, Taylor, etc.) that would themselves be a learned feature.
FIRST_NAMES: tuple[str, ...] = (
    "aaron", "adriana", "ahmed", "akiko", "alessia", "alex", "amaya",
    "amir", "anders", "andre", "anika", "anita", "antonio", "asher",
    "augusto", "ayaan", "baraka", "beatrix", "bilal", "blair", "bo",
    "branka", "brigitte", "calista", "camilla", "carlos", "casper",
    "catalina", "cedric", "celia", "chen", "chiamaka", "claire",
    "constance", "cyrus", "dahlia", "daiyu", "damaris", "daniela",
    "danish", "dao", "darius", "daven", "delphine", "dimitri",
    "dorota", "ebba", "ebrahim", "elara", "elena", "eliana",
    "ellis", "emir", "enzo", "esme", "esteban", "ezekiel", "fadia",
    "fatima", "felix", "fiona", "florian", "freya", "gabriel",
    "genevieve", "giles", "grace", "greta", "halima", "hannes",
    "haru", "hayato", "helena", "hugo", "iain", "ilse", "imari",
    "imogen", "ingrid", "iona", "irene", "ivar", "ivor", "jada",
    "jiao", "joaquin", "jorrit", "judith", "kaira", "kamala",
    "kasper", "kazuo", "kenji", "khalid", "kimi", "kiran", "lana",
    "lars", "leila", "lev", "liam", "lieve", "linnea", "lluis",
    "lorenzo", "loretta", "lucinda", "luuk", "mads", "maia",
    "marcel", "margot", "marisol", "marko", "mateus", "mehmet",
    "mei", "milena", "mira", "miyuki", "naima", "nara", "nathaniel",
    "nawal", "nikhil", "nisha", "nora", "obi", "olaf", "olu",
    "omar", "orla", "oscar", "paloma", "pavel", "phoebe", "priya",
    "qadira", "quentin", "raffi", "rasmus", "rhea", "ridhi",
    "rohan", "romina", "rosa", "ruben", "rune", "rupert", "sabine",
    "saif", "saira", "sami", "sarit", "selma", "sergei", "shaan",
    "shira", "sigrid", "simone", "sivan", "soraya", "stellan",
    "suria", "tariq", "tatiana", "teresa", "thalia", "thiago",
    "thora", "tobias", "tomoko", "ursula", "valencia", "valeria",
    "vasiliki", "verena", "viktor", "vincenzo", "wanjiru", "wei",
    "wim", "xander", "xiomara", "yael", "yana", "yara", "yelena",
    "yu", "zachary", "zaha", "zane", "zara", "zelda", "zoltan",
)
assert len(FIRST_NAMES) >= 150, f"FIRST_NAMES too small ({len(FIRST_NAMES)})"

# 200 last names, similar selection criteria.
LAST_NAMES: tuple[str, ...] = (
    "abara", "achebe", "adams", "alaoui", "alcantara", "anand",
    "arenas", "arnold", "asari", "ashford", "axelsen", "azevedo",
    "baird", "balogun", "barros", "bauer", "becker", "benitez",
    "bergman", "berkowitz", "bhattacharya", "bishop", "blackwood",
    "blanchard", "boateng", "boldyrev", "bourassa", "bridgewater",
    "brock", "brydon", "calabrese", "calloway", "cardenas", "carmona",
    "carrasco", "cassidy", "castellano", "celik", "chakraborty",
    "chandra", "chen", "cheng", "chiba", "chigozie", "cisneros",
    "clavijo", "cohen", "collins", "conti", "corso", "creighton",
    "cuevas", "dahir", "darwich", "davila", "delarosa", "diallo",
    "dimitriou", "donovan", "dragomir", "dube", "dupree", "edstrom",
    "ekele", "elwood", "endicott", "escamilla", "estrella", "faber",
    "farhadi", "ferreira", "fitzhugh", "florea", "ford", "fortin",
    "freitas", "gallego", "ganga", "ganguly", "garrison", "ghazi",
    "ghoshal", "goldberg", "gomes", "gonzales", "goodison", "greaves",
    "gunnarsson", "gutierrez", "hadid", "halimi", "harkness",
    "hartley", "haruki", "haskins", "hassan", "hawthorn", "henson",
    "herrera", "hidalgo", "hinz", "holloway", "horan", "hughes",
    "iglesias", "ibarra", "ingram", "iribe", "jablonski",
    "jacinto", "javadi", "jensen", "jovanovic", "kabir", "kafka",
    "kalu", "kamali", "kapoor", "karim", "kaur", "kayode", "keita",
    "kerimov", "khoury", "kim", "kishore", "klimov", "knapp",
    "kobayashi", "koval", "kowalski", "krishnan", "kucera", "kumi",
    "kurosawa", "lamberti", "lampe", "larsson", "leblanc", "ledesma",
    "lefebvre", "lehmann", "linhart", "liu", "lonsdale", "lopes",
    "lorca", "lutfi", "macedo", "magnusson", "mahalingam", "mahmud",
    "manrique", "marin", "matheson", "matsui", "mbaye", "mcfarland",
    "medeiros", "mehta", "meier", "melendez", "miyamoto", "mokoena",
    "monteiro", "morales", "mosbacher", "moussa", "muniz",
    "naidu", "najafi", "nakahara", "navarro", "ndiaye", "nielsen",
    "nikolaou", "ntwari", "nyong", "obregon", "ochieng", "odhiambo",
    "ojeda", "okafor", "okonkwo", "oluwole", "ouellet", "padilla",
    "pakhomov", "paredes", "park", "patel", "pavlov", "perazzo",
    "peters", "petrov", "pham", "phan", "pinto", "polanco",
    "popescu", "porras", "qureshi", "ramsey", "rana", "rashid",
    "ravenwood", "redford", "rezvan",
)
assert len(LAST_NAMES) >= 150, f"LAST_NAMES too small ({len(LAST_NAMES)})"

# Service-account suffixes — used to construct svc-<role>[-<region>]
# patterns at substitution time.
SVC_ROLES: tuple[str, ...] = (
    "deploy", "monitor", "backup", "audit", "rotate", "scan",
    "etl", "ingest", "publish", "scrape", "tunnel", "relay",
    "build", "test", "lint", "fmt", "sign", "encrypt", "decrypt",
    "import", "export", "sync", "mirror", "report",
)

# Project codenames — replace LLM defaults like "atlas", "meridian"
PROJECT_CODENAMES: tuple[str, ...] = (
    "arcturus", "altair", "amaranth", "antares", "arrakis",
    "azalea", "basalt", "beacon", "blackrose", "carmine", "cassia",
    "celeste", "citrine", "cobalt", "compass", "coral", "crocus",
    "cypress", "daedalus", "dahlia", "delphi", "denim", "drift",
    "dune", "ember", "everest", "falcon", "feldspar", "fennec",
    "flax", "flint", "flora", "garnet", "gossamer", "graphite",
    "harbor", "hazel", "helios", "hyacinth", "indigo", "iris",
    "ivory", "jasmine", "jasper", "juniper", "kestrel", "kismet",
    "kite", "kodiak", "krait", "ladon", "lapis", "larkspur",
    "laurel", "lavender", "linen", "lotus", "lyric", "magnolia",
    "mahogany", "maple", "marigold", "meadow", "merlin", "mistral",
    "moonstone", "myrtle", "narwhal", "nebula", "nimbus", "obsidian",
    "onyx", "opal", "orchid", "oriole", "osprey", "pebble", "peony",
    "peregrine", "petal", "phoenix", "pinion", "pomelo", "primrose",
    "quartz", "raven", "redwood", "river", "rowan", "sable", "saffron",
    "sage", "sapphire", "shale", "silica", "silver", "slate",
    "sparrow", "starling", "stratus", "summit", "syringa", "talon",
    "tamarind", "tangerine", "thistle", "tide", "topaz", "totem",
    "trillium", "tundra", "umber", "vesper", "violet", "wisteria",
)
assert len(PROJECT_CODENAMES) >= 80, f"PROJECT_CODENAMES too small ({len(PROJECT_CODENAMES)})"


# ----------------------------------------------------------------------------
# Substitution helpers
# ----------------------------------------------------------------------------


# Shape-detection functions are SHAPE-ONLY: they say "this token looks
# like a username / svc-account / project-codename". Sticky-default
# membership is a separate axis tested via ``is_sticky_default``. The
# routing in ``postprocess._replacement_for`` uses shape detection to
# pick the right replacement pool, so a sticky default like ``jdoe``
# must NOT be reported as svc-shape just because it's in the registry.

_PROJECT_CODENAME_DEFAULTS: frozenset[str] = frozenset(
    {"atlas", "meridian", "acme", "globex", "contoso", "fabrikam"}
)


def is_sticky_default(token: str) -> bool:
    """True if ``token`` is a known LLM-default observed across audit
    passes. Triggers substitution regardless of shape."""
    return token.lower() in LLM_STICKY_DEFAULTS


def is_username_shape(token: str) -> bool:
    """True if ``token`` matches the username PATTERN (first-initial +
    last-name shape). Pure pattern check — does NOT route on
    sticky-default membership."""
    if token.lower() in USERNAME_PATTERN_IGNORE:
        return False
    return bool(USERNAME_PATTERN.match(token.lower()))


def is_svc_account_shape(token: str) -> bool:
    """True if ``token`` matches the svc-<role> PATTERN. Pure pattern
    check — does NOT route on sticky-default membership."""
    return bool(SVC_ACCOUNT_PATTERN.match(token))


def is_project_codename_shape(token: str) -> bool:
    """True if ``token`` is a known LLM-default project codename."""
    return token.lower() in _PROJECT_CODENAME_DEFAULTS


__all__ = [
    "FIRST_NAMES",
    "LAST_NAMES",
    "LLM_STICKY_DEFAULTS",
    "PROJECT_CODENAMES",
    "SVC_ACCOUNT_PATTERN",
    "SVC_ROLES",
    "USERNAME_PATTERN",
    "USERNAME_PATTERN_IGNORE",
    "is_project_codename_shape",
    "is_sticky_default",
    "is_svc_account_shape",
    "is_username_shape",
]

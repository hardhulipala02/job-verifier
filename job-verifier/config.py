"""Centralized configuration loaded from environment / .env file.

All sensitive credentials live in a git-ignored ``.env`` file (see
``.env.example``). External services are optional: when their credentials are
absent the pipeline degrades gracefully instead of crashing.
"""
import os

from dotenv import load_dotenv

load_dotenv()


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# --- Google Gemini ---------------------------------------------------------
GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY") or None
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# --- Neo4j -----------------------------------------------------------------
NEO4J_URI: str | None = os.getenv("NEO4J_URI") or None
NEO4J_USER: str | None = os.getenv("NEO4J_USER") or None
NEO4J_PASSWORD: str | None = os.getenv("NEO4J_PASSWORD") or None

# --- LLM retry / backoff ---------------------------------------------------
LLM_MAX_RETRIES: int = _get_int("LLM_MAX_RETRIES", 4)
LLM_BACKOFF_BASE_SECONDS: float = _get_float("LLM_BACKOFF_BASE_SECONDS", 1.0)

# --- URL threat intelligence (VirusTotal / URLScan) ------------------------
# Optional API keys. When unset, the threat-intel node still runs and defangs
# URLs but reports "reputation check skipped".
VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
URLSCAN_API_KEY: str | None = os.getenv("URLSCAN_API_KEY") or None
THREAT_INTEL_TIMEOUT: float = _get_float("JOBVERIFIER_THREAT_TIMEOUT", 8.0)


def threat_intel_enabled() -> bool:
    """Whether any URL-reputation provider is configured."""
    return bool(VIRUSTOTAL_API_KEY or URLSCAN_API_KEY)


# --- DNS infrastructure mapping --------------------------------------------
DNS_RESOLVE_ENABLED: bool = (os.getenv("JOBVERIFIER_RESOLVE_DNS", "") or "").strip(
).lower() in {"1", "true", "yes", "on"}
DNS_TIMEOUT: float = _get_float("JOBVERIFIER_DNS_TIMEOUT", 4.0)


def dns_resolve_enabled() -> bool:
    """Whether async A/NS resolution of extracted domains is turned on."""
    return DNS_RESOLVE_ENABLED


# --- Role existence verification (best-effort web search) ------------------
# When enabled, the pipeline searches the web to check whether the advertised
# role plausibly exists at the claimed company. It is best-effort and degrades
# gracefully (network failures simply report "could not verify"). Off by default
# so tests/CI stay offline and deterministic.
ROLE_CHECK_ENABLED: bool = (os.getenv("JOBVERIFIER_VERIFY_ROLE", "") or "").strip(
).lower() in {"1", "true", "yes", "on"}
ROLE_CHECK_TIMEOUT: float = _get_float("JOBVERIFIER_ROLE_TIMEOUT", 6.0)


def role_check_enabled() -> bool:
    """Whether best-effort web role verification is turned on."""
    return ROLE_CHECK_ENABLED


# --- Mail bot (forward-to-address flow) ------------------------------------
# The bot watches BOT_EMAIL over IMAP and replies over SMTP. Username defaults
# to BOT_EMAIL when not given separately.
BOT_EMAIL: str | None = os.getenv("JOBVERIFIER_BOT_EMAIL") or None
# Gmail shows App Passwords grouped with spaces; strip them so login works.
BOT_PASSWORD: str | None = (
    os.getenv("JOBVERIFIER_BOT_PASSWORD", "").replace(" ", "") or None
)
IMAP_HOST: str = os.getenv("JOBVERIFIER_IMAP_HOST", "imap.gmail.com")
IMAP_PORT: int = _get_int("JOBVERIFIER_IMAP_PORT", 993)
SMTP_HOST: str = os.getenv("JOBVERIFIER_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = _get_int("JOBVERIFIER_SMTP_PORT", 587)
MAILBOX: str = os.getenv("JOBVERIFIER_MAILBOX", "INBOX")
POLL_INTERVAL_SECONDS: int = _get_int("JOBVERIFIER_POLL_INTERVAL", 30)


def llm_enabled() -> bool:
    """Whether a Gemini API key is configured."""
    return bool(GOOGLE_API_KEY)


def neo4j_enabled() -> bool:
    """Whether Neo4j credentials are fully configured."""
    return bool(NEO4J_URI and NEO4J_USER and NEO4J_PASSWORD)


def mailbot_enabled() -> bool:
    """Whether mailbox credentials are configured."""
    return bool(BOT_EMAIL and BOT_PASSWORD)

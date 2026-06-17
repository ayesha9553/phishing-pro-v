"""Application configuration loaded from environment variables."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
_project_root = Path(__file__).resolve().parent.parent
load_dotenv(_project_root / ".env")


class Settings:
    """Application settings with sensible defaults."""

    # Paths
    PROJECT_ROOT: Path = _project_root
    DATABASE_URL: str = os.getenv("DATABASE_URL", "data/phishing.db")
    DATABASE_PATH: Path = _project_root / os.getenv("DATABASE_URL", "data/phishing.db")

    # VirusTotal (optional)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_ENABLED: bool = bool(os.getenv("VIRUSTOTAL_API_KEY", ""))

    # PhishTank (optional)
    PHISHTANK_APP_KEY: str = os.getenv("PHISHTANK_APP_KEY", "")

    # Generative AI
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "none")  # 'openai' | 'gemini' | 'none'
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    AI_ENABLED: bool = os.getenv("AI_PROVIDER", "none").lower() not in ("none", "")

    # Email Gateway thresholds
    GATEWAY_QUARANTINE_THRESHOLD: int = int(os.getenv("GATEWAY_QUARANTINE_THRESHOLD", "60"))
    GATEWAY_BLOCK_THRESHOLD: int = int(os.getenv("GATEWAY_BLOCK_THRESHOLD", "85"))

    # IMAP Polling
    IMAP_HOST: str = os.getenv("IMAP_HOST", "")
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    IMAP_USER: str = os.getenv("IMAP_USER", "")
    IMAP_PASS: str = os.getenv("IMAP_PASS", "")
    IMAP_FOLDER: str = os.getenv("IMAP_FOLDER", "INBOX")
    IMAP_POLL_INTERVAL: int = int(os.getenv("IMAP_POLL_INTERVAL", "60"))
    IMAP_ENABLED: bool = bool(os.getenv("IMAP_HOST", ""))

    # Server
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))

    # Frontend path
    FRONTEND_DIR: Path = _project_root / "frontend"

    @classmethod
    def ensure_data_dir(cls):
        """Ensure the data directory exists."""
        cls.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()

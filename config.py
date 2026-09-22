from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RESULTS_FILE = BASE_DIR / "data" / "results.json"
UPLOAD_DIR = BASE_DIR / "logs" / "uploads"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_LOG_EXTENSIONS = {".txt", ".log"}
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW_MINUTES = 10
ACCOUNT_TAKEOVER_THRESHOLD = 3
ACCOUNT_TAKEOVER_WINDOW_MINUTES = 30
POST_AUTH_COMMAND_WINDOW_SECONDS = 300
CORRELATION_WINDOW_SECONDS = 600
# Static fallback hours preserved for baseline comparison and cold-start reference
UNUSUAL_HOURS = {0, 1, 2, 3, 4, 5, 22, 23}
SUSPICIOUS_IPS = {"185.199.110.42", "45.77.65.19", "185.220.101.45", "203.0.113.77", "45.155.204.12"}

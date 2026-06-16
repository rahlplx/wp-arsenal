"""
wp_connect.py — Shared connection & utility library for WP-Arsenal scripts
==========================================================================
USAGE:  from wp_connect import WPConnection, add_connection_args, print_banner

Every script imports this instead of repeating boilerplate.
Provides:
  - Argparse base with --host/--user/--pass/--wp-path/--db-*/--dry-run/--quiet
  - SSH connect with retry + keepalive
  - SFTP helper (read, write, chmod)
  - MySQL query helper
  - HTTP probe helper (curl via SSH)
  - Colour-coded result printer
"""

import argparse
import sys
import time
import socket
import re
from typing import Optional, Tuple, List

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: paramiko not installed. Run: pip install paramiko")


# ── Colour codes (degrade gracefully if not a tty) ─────────────────────────
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

RED    = lambda t: _c("31", t)
GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)


# ── Argparse helpers ────────────────────────────────────────────────────────
def add_connection_args(parser: argparse.ArgumentParser) -> None:
    """Add standard SSH + DB + WP arguments to any argparse parser."""
    g = parser.add_argument_group("Connection")
    g.add_argument("--host",    required=True,  help="SSH hostname (e.g. access-XXXXX.webspace-host.com)")
    g.add_argument("--user",    required=True,  help="SSH username")
    g.add_argument("--password", required=True, help="SSH password")
    g.add_argument("--port",    type=int, default=22, help="SSH port (default: 22)")
    g.add_argument("--wp-path", required=True,  dest="wp_path",
                   help="Absolute path to WP root on the server (e.g. /var/www/html/yoursite)")

    g2 = parser.add_argument_group("Database (optional — needed for DB checks)")
    g2.add_argument("--db-host",   dest="db_host",   default="", help="MySQL hostname")
    g2.add_argument("--db-user",   dest="db_user",   default="", help="MySQL username")
    g2.add_argument("--db-pass",   dest="db_pass",   default="", help="MySQL password")
    g2.add_argument("--db-name",   dest="db_name",   default="", help="MySQL database name")
    g2.add_argument("--db-prefix", dest="db_prefix", default="wp_", help="WP table prefix (default: wp_)")

    g3 = parser.add_argument_group("Behaviour")
    g3.add_argument("--dry-run", action="store_true",
                    help="Show what would be done without making changes")
    g3.add_argument("--quiet",   action="store_true", help="Suppress progress output")
    g3.add_argument("--json",    action="store_true", help="Output results as JSON")
    g3.add_argument("--site-url", dest="site_url",   default="",
                    help="Public URL for HTTP probes (e.g. https://yoursite.com)")
    g3.add_argument("--alert-email", dest="alert_email", default="",
                    help="Email address for security alerts")
    g3.add_argument("--trusted-cidrs", dest="trusted_cidrs", default="",
                    help="Comma-separated IP prefixes to never alert/block (e.g. 82.165.,127.0.0.1)")
    g3.add_argument("--blocked-cidrs", dest="blocked_cidrs", default="",
                    help="Comma-separated IP prefixes to block")
    g3.add_argument("--config", metavar="FILE", default=None,
                    help="Path to config.yaml (auto-detected if omitted)")


def print_banner(title: str, dry_run: bool = False) -> None:
    bar = "═" * 68
    print(f"\n{BOLD(bar)}")
    print(f"  {BOLD(title)}")
    if dry_run:
        print(f"  {YELLOW('DRY-RUN MODE — no changes will be made')}")
    print(f"{BOLD(bar)}\n")


def ok(msg: str)   -> None: print(f"  {GREEN('✓')} {msg}", flush=True)
def warn(msg: str) -> None: print(f"  {YELLOW('⚠')} {msg}", flush=True)
def err(msg: str)  -> None: print(f"  {RED('✗')} {msg}", flush=True)
def info(msg: str) -> None: print(f"  {CYAN('·')} {msg}", flush=True)
def section(title: str) -> None:
    print(f"\n  {BOLD('─── ' + title + ' ───')}", flush=True)


# ── Connection class ────────────────────────────────────────────────────────
class WPConnection:
    """
    Manages SSH + SFTP + MySQL connections to a WordPress hosting server.

    Usage:
        wp = WPConnection(args)
        wp.connect()
        out = wp.ssh("find /path -name '*.php'")
        wp.sftp_write("remote/path/file.php", content_bytes)
        rows = wp.db("SELECT * FROM wp_options LIMIT 5")
        wp.close()

    Or as context manager:
        with WPConnection(args) as wp:
            print(wp.ssh("whoami"))
    """

    def __init__(self, args: argparse.Namespace):
        self.host      = args.host
        self.user      = args.user
        self.password  = args.password
        self.port      = getattr(args, "port", 22)
        self.wp_path   = args.wp_path.rstrip("/")
        self.db_host   = getattr(args, "db_host",   "")
        self.db_user   = getattr(args, "db_user",   "")
        self.db_pass   = getattr(args, "db_pass",   "")
        self.db_name   = getattr(args, "db_name",   "")
        self.db_prefix = getattr(args, "db_prefix", "wp_")
        self.site_url  = getattr(args, "site_url",  "")
        self.dry_run   = getattr(args, "dry_run",   False)
        self.quiet     = getattr(args, "quiet",     False)
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp:   Optional[paramiko.SFTPClient] = None

    # ── lifecycle ──────────────────────────────────────────────────────────
    def connect(self, retries: int = 3, delay: float = 5.0) -> None:
        """Connect SSH with retry. Raises SystemExit on persistent failure."""
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    self.host, port=self.port,
                    username=self.user, password=self.password,
                    timeout=30,
                    banner_timeout=30,
                    auth_timeout=30,
                )
                # Keepalive so long-running scripts don't drop
                client.get_transport().set_keepalive(30)
                self._client = client
                if not self.quiet:
                    ok(f"SSH connected to {self.host} (attempt {attempt})")
                return
            except paramiko.AuthenticationException:
                sys.exit(RED(f"AUTH FAILED for {self.user}@{self.host} — check credentials"))
            except (socket.timeout, paramiko.SSHException, OSError) as exc:
                last_exc = exc
                if attempt < retries:
                    warn(f"Connection attempt {attempt} failed ({exc}), retrying in {delay}s…")
                    time.sleep(delay)
        sys.exit(RED(f"Cannot connect to {self.host} after {retries} attempts: {last_exc}"))

    def close(self) -> None:
        if self._sftp:
            self._sftp.close()
        if self._client:
            self._client.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ── SSH command execution ──────────────────────────────────────────────
    def ssh(self, cmd: str, timeout: int = 120) -> str:
        """Run a shell command, return stdout as string. Stderr is discarded."""
        if not self._client:
            raise RuntimeError("Not connected — call connect() first")
        _, stdout, _ = self._client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", "replace").strip()

    def ssh2(self, cmd: str, timeout: int = 120) -> Tuple[str, str]:
        """Run a shell command, return (stdout, stderr) tuple."""
        if not self._client:
            raise RuntimeError("Not connected — call connect() first")
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        return (
            stdout.read().decode("utf-8", "replace").strip(),
            stderr.read().decode("utf-8", "replace").strip(),
        )

    # ── SFTP helpers ───────────────────────────────────────────────────────
    def _get_sftp(self) -> paramiko.SFTPClient:
        if not self._sftp:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def sftp_read(self, remote_path: str) -> bytes:
        """Read a remote file as bytes. Returns b'' if not found or unreadable."""
        sftp = self._get_sftp()
        try:
            with sftp.open(remote_path, "rb") as f:
                return f.read()
        except (IOError, OSError):
            return b""

    def sftp_write(self, remote_path: str, content: bytes) -> bool:
        """
        Write bytes to remote file using write-only mode.
        Works even when file is --w------- (write-only, unreadable by web server).
        Returns True on success.
        """
        if self.dry_run:
            info(f"[DRY-RUN] Would write {len(content)} bytes to {remote_path}")
            return True
        sftp = self._get_sftp()
        try:
            with sftp.open(remote_path, "wb") as f:
                f.write(content)
            return True
        except (IOError, OSError) as exc:
            err(f"SFTP write failed for {remote_path}: {exc}")
            return False

    def sftp_chmod(self, remote_path: str, mode: int) -> bool:
        """chmod a remote path. mode is octal int e.g. 0o644."""
        if self.dry_run:
            info(f"[DRY-RUN] Would chmod {oct(mode)} {remote_path}")
            return True
        sftp = self._get_sftp()
        try:
            sftp.chmod(remote_path, mode)
            return True
        except (IOError, OSError) as exc:
            err(f"SFTP chmod failed for {remote_path}: {exc}")
            return False

    # ── Database helper ────────────────────────────────────────────────────
    def db(self, sql: str, timeout: int = 30) -> str:
        """Run a MySQL query via SSH. Returns result as string."""
        if not all([self.db_host, self.db_user, self.db_pass, self.db_name]):
            warn("DB credentials not configured — skipping DB query")
            return ""
        # Base64-encode the query so its content (quotes, $, backticks, etc.)
        # can never be interpreted by the remote shell — only the SQL engine
        # ever sees the literal bytes. The password goes via MYSQL_PWD instead
        # of -p so it never shows up in the remote `ps` output.
        import base64
        sql_b64 = base64.b64encode(sql.encode("utf-8")).decode("ascii")
        pass_escaped = self.db_pass.replace("'", "'\\''")
        cmd = (
            f"MYSQL_PWD='{pass_escaped}' bash -c '"
            f"echo {sql_b64} | base64 -d | mysql -h \"{self.db_host}\" -u \"{self.db_user}\" \"{self.db_name}\"'"
            f" 2>/dev/null"
        )
        return self.ssh(cmd, timeout=timeout)

    @staticmethod
    def sql_escape(value: str) -> str:
        """Escape a string for safe interpolation inside a single-quoted SQL literal."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def sql_slug(value: str) -> str:
        """
        Validate a value intended to be a WP slug/login/theme-stylesheet
        (alphanumeric, dash, underscore, dot only). Raises ValueError if
        the value contains anything else — use for values that should
        never legitimately contain quotes or SQL metacharacters.
        """
        if not re.match(r"^[A-Za-z0-9_.\-]+$", value):
            raise ValueError(f"Invalid slug/identifier: {value!r} — only [A-Za-z0-9_.-] allowed")
        return value

    def db_write(self, sql: str, timeout: int = 30) -> str:
        """Run a mutating MySQL query. Respects --dry-run."""
        if self.dry_run:
            info(f"[DRY-RUN] Would run SQL: {sql[:100]}")
            return ""
        return self.db(sql, timeout)

    # ── HTTP probe helper ──────────────────────────────────────────────────
    def http_code(self, url: str, timeout: int = 20) -> str:
        """Return HTTP status code string for a URL (e.g. '200', '403')."""
        cmd = f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time {timeout} '{url}' 2>/dev/null"
        return self.ssh(cmd, timeout + 5)

    def http_body(self, url: str, timeout: int = 25) -> str:
        """Return HTTP response body for a URL."""
        cmd = f"curl -sk --max-time {timeout} '{url}' 2>/dev/null"
        return self.ssh(cmd, timeout + 5)

    # ── WordPress path helpers ─────────────────────────────────────────────
    def wp(self, rel: str) -> str:
        """Return absolute path for a path relative to WP root."""
        return f"{self.wp_path}/{rel.lstrip('/')}"

    def wp_exists(self, rel: str) -> bool:
        """Check if a file/dir exists relative to WP root."""
        result = self.ssh(f"test -e '{self.wp(rel)}' && echo Y || echo N")
        return result == "Y"

    def wp_readable(self, rel: str) -> bool:
        """Check if a file is readable relative to WP root."""
        result = self.ssh(f"test -r '{self.wp(rel)}' && echo Y || echo N")
        return result == "Y"


# ── Convenience: build WPConnection from CLI args ───────────────────────────
def connect_from_args(args: argparse.Namespace) -> WPConnection:
    """Construct and connect a WPConnection from parsed argparse args."""
    # Merge config.yaml values before connecting
    try:
        import config_loader
        args = config_loader.load_config(args)
    except ImportError:
        pass
    # Normalise list args that might come in as comma-separated strings
    for attr in ("trusted_cidrs", "blocked_cidrs"):
        val = getattr(args, attr, "") or ""
        if isinstance(val, str):
            setattr(args, attr, [v.strip() for v in val.split(",") if v.strip()])
    wp = WPConnection(args)
    wp.connect()
    return wp


# ── Result accumulator for JSON output ─────────────────────────────────────
class AuditResult:
    """Accumulate findings and print a structured summary."""

    def __init__(self, script_name: str):
        self.script  = script_name
        self.findings: list = []
        self.errors:   list = []
        self.stats:    dict = {}

    def add(self, severity: str, category: str, detail: str, path: str = "") -> None:
        """severity: CRITICAL | HIGH | MEDIUM | LOW | INFO"""
        self.findings.append({
            "severity": severity,
            "category": category,
            "detail":   detail,
            "path":     path,
        })

    def stat(self, key: str, value) -> None:
        self.stats[key] = value

    def print_summary(self) -> None:
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        print(f"\n{'═'*68}")
        print(BOLD(f"  AUDIT SUMMARY — {self.script}"))
        print(f"{'═'*68}")
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            n = counts.get(sev, 0)
            if n:
                colour = {
                    "CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
                    "LOW": CYAN, "INFO": DIM
                }.get(sev, str)
                print(f"  {colour(sev):12s}  {n} finding(s)")
        for k, v in self.stats.items():
            print(f"  {DIM(k+':')} {v}")
        print(f"{'═'*68}\n")

    def to_dict(self) -> dict:
        return {
            "script":   self.script,
            "findings": self.findings,
            "stats":    self.stats,
            "errors":   self.errors,
        }

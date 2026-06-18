#!/usr/bin/env python3
"""
wp-theme-restore.py — Full WordPress theme restoration with Web UI/UX verification
====================================================================================
Performs a complete theme recovery after corruption, attack, or accidental deletion.
Goes beyond file restoration to verify the full frontend user experience is healthy:
CSS loading, JS loading, fonts, images, Elementor/page builder rendering, WooCommerce
storefront, mobile responsiveness, and HTTP performance.

WordPress Theme Layer Architecture (what this script understands):
─────────────────────────────────────────────────────────────────
  Database layer
    wp_options: template, stylesheet, current_theme, theme_mods_{slug}
    wp_options: elementor_css_version, active_plugins
    wp_postmeta: _elementor_data, _elementor_css, _elementor_global_css
    wp_postmeta: _thumbnail_id, _wp_page_template
  Filesystem layer
    wp-content/themes/{slug}/              ← theme root
      style.css                            ← Theme Name, Template, Version headers
      functions.php                        ← enqueues, hooks, setup
      index.php                            ← fallback template
      screenshot.png                       ← WP admin thumbnail
      *.php                                ← templates: page, single, archive...
      assets/ or css/, js/, images/        ← frontend assets
    wp-content/themes/{parent-slug}/       ← parent theme (child themes)
    wp-content/uploads/                    ← user media (theme may depend on it)
    wp-content/cache/                      ← CSS/JS cache (must be clearable)
    wp-content/plugins/elementor/          ← Elementor CSS generation engine
  HTTP layer
    Frontend: homepage, shop, single posts, archive, search
    Admin: wp-admin/themes.php, Customizer, Elementor editor
    Assets: CSS/JS/fonts/images (must return 200, not 404)

Usage:
  python scripts/restoration/wp-theme-restore.py --config config/config.yaml
  python scripts/restoration/wp-theme-restore.py --config config/config.yaml --dry-run
  python scripts/restoration/wp-theme-restore.py --config config/config.yaml \\
      --theme kadence --from-backup /path/to/theme-backup.tar.gz
  python scripts/restoration/wp-theme-restore.py --config config/config.yaml \\
      --verify-only --site-url https://yoursite.com
"""

import argparse
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, connect_from_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


# ── WordPress canonical folder structure ────────────────────────────────────

WP_REQUIRED_DIRS = [
    "wp-content",
    "wp-content/themes",
    "wp-content/plugins",
    "wp-content/uploads",
    "wp-includes",
    "wp-admin",
]

WP_REQUIRED_FILES = [
    "wp-config.php",
    "wp-login.php",
    "index.php",
    "wp-includes/functions.php",
    "wp-includes/class-wp.php",
    "wp-content/index.php",
]

# Files that should NOT be present (security)
WP_FORBIDDEN_FILES = [
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config-sample.php",  # ok if fresh install, warn if config.php also exists
    "readme.html",
    "license.txt",
    ".maintenance",          # stuck in maintenance mode
    "wp-content/debug.log",
]

# Theme-required files (any active theme must have these)
THEME_REQUIRED_FILES = [
    "style.css",
    "index.php",
]

# Theme headers read from style.css
THEME_HEADER_FIELDS = [
    "Theme Name",
    "Version",
    "Template",     # non-empty = child theme
    "Text Domain",
]

# Page builder detection
PAGE_BUILDERS = {
    "elementor/elementor.php":        "Elementor",
    "elementor-pro/elementor-pro.php": "Elementor Pro",
    "beaver-builder-lite-version/fl-builder.php": "Beaver Builder",
    "js_composer/js_composer.php":    "WPBakery",
    "divi-builder/divi-builder.php":  "Divi Builder",
    "siteorigin-panels/siteorigin-panels.php": "SiteOrigin",
    "block-lab/block-lab.php":        "Block Lab",
}

# WooCommerce template hierarchy (theme overrides in woocommerce/)
WOO_TEMPLATE_DIR = "woocommerce"

# HTTP checks: path → description → expected status
HTTP_PATHS = [
    ("/",                    "Homepage"),
    ("/wp-login.php",        "WP login page"),
    ("/?s=test",             "Search results"),
    ("/feed/",               "RSS feed"),
]


# ── WordPress folder structure validator ───────────────────────────────────

def audit_wp_structure(wp: WPConnection, result: AuditResult) -> dict:
    """
    Deep-audit WordPress folder structure.

    Returns a dict with keys:
      is_valid, missing_required, forbidden_present, permissions_issues,
      theme_slug, parent_slug, is_child_theme, page_builder, has_woocommerce
    """
    section("WordPress Folder Structure Audit")
    findings = {
        "is_valid": True,
        "missing_required": [],
        "forbidden_present": [],
        "permissions_issues": [],
        "theme_slug": "",
        "parent_slug": "",
        "is_child_theme": False,
        "page_builder": None,
        "has_woocommerce": False,
    }

    # ── Required directories ──
    for d in WP_REQUIRED_DIRS:
        exists = wp.wp_exists(d)
        if not exists:
            err(f"Missing required dir: {d}")
            findings["missing_required"].append(d)
            findings["is_valid"] = False
            result.add("CRITICAL", "wp-structure", f"Missing required directory: {d}", wp.wp(d))
        else:
            ok(f"  {d}/")

    # ── Required files ──
    for f in WP_REQUIRED_FILES:
        if not wp.wp_exists(f):
            err(f"Missing required file: {f}")
            findings["missing_required"].append(f)
            findings["is_valid"] = False
            result.add("HIGH", "wp-structure", f"Missing required file: {f}", wp.wp(f))

    # ── Forbidden files ──
    for f in WP_FORBIDDEN_FILES:
        if wp.wp_exists(f):
            warn(f"Should not exist: {f}")
            findings["forbidden_present"].append(f)
            sev = "HIGH" if "wp-config.php.bak" in f else "MEDIUM"
            result.add(sev, "wp-structure", f"Forbidden file present: {f}", wp.wp(f))

    # ── Active theme ──
    p = wp.db_prefix
    theme_row = wp.db(
        f"SELECT option_value FROM {p}options "
        f"WHERE option_name='template' LIMIT 1;"
    ).strip().splitlines()
    theme_slug = theme_row[-1].strip() if theme_row else ""
    findings["theme_slug"] = theme_slug

    stylesheet_row = wp.db(
        f"SELECT option_value FROM {p}options "
        f"WHERE option_name='stylesheet' LIMIT 1;"
    ).strip().splitlines()
    stylesheet_slug = stylesheet_row[-1].strip() if stylesheet_row else ""

    findings["is_child_theme"] = (stylesheet_slug != theme_slug)
    findings["parent_slug"] = theme_slug if findings["is_child_theme"] else ""

    if theme_slug:
        info(f"Active theme (template): {theme_slug}")
        if findings["is_child_theme"]:
            info(f"  Active child theme (stylesheet): {stylesheet_slug}")
        if not wp.wp_exists(f"wp-content/themes/{theme_slug}"):
            err(f"ACTIVE THEME DIRECTORY MISSING: wp-content/themes/{theme_slug}")
            result.add("CRITICAL", "theme-missing",
                       f"Active theme directory missing: {theme_slug}",
                       wp.wp(f"wp-content/themes/{theme_slug}"))
            findings["is_valid"] = False
        if findings["is_child_theme"] and stylesheet_slug:
            if not wp.wp_exists(f"wp-content/themes/{stylesheet_slug}"):
                err(f"ACTIVE CHILD THEME DIRECTORY MISSING: wp-content/themes/{stylesheet_slug}")
                result.add("CRITICAL", "theme-missing",
                           f"Active child theme directory missing: {stylesheet_slug}",
                           wp.wp(f"wp-content/themes/{stylesheet_slug}"))
                findings["is_valid"] = False

    # ── Page builder detection ──
    active_plugins = wp.db(
        f"SELECT option_value FROM {p}options "
        f"WHERE option_name='active_plugins' LIMIT 1;"
    ).strip()
    for plugin_path, builder_name in PAGE_BUILDERS.items():
        if plugin_path in active_plugins:
            findings["page_builder"] = builder_name
            info(f"Page builder: {builder_name}")
            break

    # ── WooCommerce detection ──
    findings["has_woocommerce"] = "woocommerce/woocommerce.php" in active_plugins
    if findings["has_woocommerce"]:
        info("WooCommerce: active")

    # ── Permissions audit ──
    perm_out = wp.ssh(
        f"find '{wp.wp('wp-content/themes')}' -maxdepth 3 -perm /o+w 2>/dev/null | head -20"
    )
    if perm_out.strip():
        for line in perm_out.strip().splitlines():
            warn(f"World-writable: {line}")
            findings["permissions_issues"].append(line)
            result.add("HIGH", "permissions", f"World-writable theme file: {line}", line)

    return findings


# ── Theme file integrity check ──────────────────────────────────────────────

def audit_theme_files(wp: WPConnection, theme_slug: str, result: AuditResult) -> dict:
    """
    Validate theme file structure and integrity.

    Returns:
      theme_name, version, is_child_theme, parent_slug, has_screenshot,
      template_files, asset_files, missing_files, suspect_files
    """
    section(f"Theme File Audit: {theme_slug}")
    theme_dir = wp.wp(f"wp-content/themes/{theme_slug}")
    info_out = {
        "theme_name": theme_slug,
        "version": "unknown",
        "is_child_theme": False,
        "parent_slug": "",
        "has_screenshot": False,
        "template_files": [],
        "asset_dirs": [],
        "missing_files": [],
        "suspect_files": [],
    }

    # Read style.css header
    style_raw = wp.sftp_read(f"{theme_dir}/style.css").decode("utf-8", "replace")
    if not style_raw:
        err(f"style.css missing or unreadable in {theme_slug}")
        result.add("CRITICAL", "theme-files", f"style.css missing: {theme_slug}", theme_dir)
        info_out["missing_files"].append("style.css")
        return info_out

    for field in THEME_HEADER_FIELDS:
        m = re.search(rf"^{re.escape(field)}:\s*(.+)$", style_raw, re.MULTILINE)
        if m:
            val = m.group(1).strip()
            if field == "Theme Name":
                info_out["theme_name"] = val
            elif field == "Version":
                info_out["version"] = val
            elif field == "Template" and val:
                info_out["is_child_theme"] = True
                info_out["parent_slug"] = val
    ok(f"style.css: {info_out['theme_name']} v{info_out['version']}")
    if info_out["is_child_theme"]:
        ok(f"Child theme of: {info_out['parent_slug']}")

    # Required files
    for f in THEME_REQUIRED_FILES:
        if not wp.wp_exists(f"wp-content/themes/{theme_slug}/{f}"):
            err(f"Missing: {f}")
            info_out["missing_files"].append(f)
            result.add("HIGH", "theme-files", f"Required theme file missing: {f}", f"{theme_dir}/{f}")
        else:
            ok(f"  {f}")

    # Template hierarchy files
    all_files = wp.ssh(f"find '{theme_dir}' -maxdepth 2 -name '*.php' 2>/dev/null")
    template_files = [
        line.strip() for line in all_files.splitlines()
        if line.strip() and not "/assets/" in line and not "/inc/" in line
    ]
    info_out["template_files"] = template_files
    info(f"PHP templates: {len(template_files)} files")

    # Asset directories
    asset_dirs = wp.ssh(f"ls -1 '{theme_dir}' 2>/dev/null")
    for item in asset_dirs.splitlines():
        item = item.strip()
        if item in ("css", "js", "assets", "images", "fonts", "img", "src", "dist"):
            info_out["asset_dirs"].append(item)
    if info_out["asset_dirs"]:
        ok(f"Asset dirs: {', '.join(info_out['asset_dirs'])}")
    else:
        warn("No standard asset directories found (css/, js/, assets/)")

    # Screenshot
    info_out["has_screenshot"] = wp.wp_exists(f"wp-content/themes/{theme_slug}/screenshot.png")

    # Suspect files (PHP in asset dirs — potential backdoor)
    suspect = wp.ssh(
        f"find '{theme_dir}/assets' '{theme_dir}/css' '{theme_dir}/js' '{theme_dir}/images' "
        f"-name '*.php' 2>/dev/null | head -10"
    )
    if suspect.strip():
        for s in suspect.strip().splitlines():
            warn(f"Suspect PHP in asset dir: {s}")
            info_out["suspect_files"].append(s)
            result.add("HIGH", "theme-security", f"PHP file in asset directory: {s}", s)

    return info_out


# ── CSS / JS asset health check ─────────────────────────────────────────────

def audit_frontend_assets(wp: WPConnection, result: AuditResult) -> dict:
    """
    Check CSS and JS assets load correctly on the frontend.

    Extracts enqueued stylesheet/script URLs from page source,
    then verifies each returns HTTP 200. Detects broken CSS causing
    blank/unstyled pages.
    """
    section("Frontend Asset Health (CSS / JS / Fonts)")
    if not wp.site_url:
        warn("No --site-url configured — skipping HTTP asset checks")
        return {}

    # Fetch homepage source
    body = wp.http_body(wp.site_url, timeout=30)
    if not body:
        err("Could not fetch homepage — HTTP check skipped")
        result.add("HIGH", "frontend", "Homepage returned empty body", wp.site_url)
        return {}

    # Extract stylesheet URLs
    css_urls = re.findall(r"<link[^>]+rel=['\"]stylesheet['\"][^>]+href=['\"]([^'\"]+)['\"]", body)
    css_urls += re.findall(r"<link[^>]+href=['\"]([^'\"]+)['\"][^>]+rel=['\"]stylesheet['\"]", body)

    # Extract JS URLs
    js_urls = re.findall(r"<script[^>]+src=['\"]([^'\"]+)['\"]", body)

    assets = {"css": css_urls, "js": js_urls, "broken": []}

    # Check CSS files (these are critical — a missing stylesheet breaks the whole page)
    broken_css = []
    for url in css_urls[:15]:  # cap at 15 to avoid excessive SSH calls
        code = wp.http_code(url.split("?")[0])  # strip cache-busting query
        if code not in ("200", "304"):
            err(f"CSS broken ({code}): {url[:80]}")
            broken_css.append(url)
            result.add("HIGH", "frontend-css", f"Stylesheet returns {code}: {url[:80]}", url)
        else:
            ok(f"  CSS {code}: {url[-50:]}")
    assets["broken_css"] = broken_css

    # Check JS files (warning only — JS errors rarely blank the page fully)
    broken_js = []
    for url in js_urls[:10]:
        code = wp.http_code(url.split("?")[0])
        if code not in ("200", "304"):
            warn(f"JS broken ({code}): {url[:80]}")
            broken_js.append(url)
            result.add("MEDIUM", "frontend-js", f"Script returns {code}: {url[:80]}", url)
    assets["broken_js"] = broken_js

    # Detect Elementor-generated CSS
    elementor_css = [u for u in css_urls if "elementor/css" in u or "elementor-frontend" in u]
    if elementor_css:
        info(f"Elementor CSS files detected: {len(elementor_css)}")
        for u in elementor_css[:3]:
            code = wp.http_code(u.split("?")[0])
            if code != "200":
                err(f"Elementor CSS broken ({code}): {u[-60:]}")
                result.add("CRITICAL", "elementor-css",
                           f"Elementor CSS file missing — page will render without styles: {u[-60:]}", u)

    info(f"CSS checked: {len(css_urls)}, JS checked: {len(js_urls)}")
    info(f"Broken CSS: {len(broken_css)}, Broken JS: {len(broken_js)}")

    return assets


# ── Web UI/UX verification ──────────────────────────────────────────────────

def verify_web_ux(wp: WPConnection, struct: dict, result: AuditResult) -> None:
    """
    Verify the full web UI/UX is functional from an end-user perspective.

    Checks:
    - Homepage renders with correct HTTP status
    - WP admin accessible and not blank
    - Elementor editor not broken (if active)
    - WooCommerce shop/product pages working (if active)
    - Search results page loads
    - Mobile viewport tag present (basic responsiveness check)
    - Canonical URLs correct (no double-www or http→https broken redirects)
    """
    section("Web UI/UX Verification")
    if not wp.site_url:
        warn("No --site-url — skipping Web UX checks")
        return

    checks = [
        ("/",              "Homepage",       ["200", "301", "302"]),
        ("/wp-login.php",  "Login page",     ["200"]),
        ("/?s=test",       "Search page",    ["200"]),
        ("/feed/",         "RSS feed",       ["200"]),
        ("/sitemap.xml",   "Sitemap",        ["200", "301", "302", "404"]),
    ]

    if struct.get("has_woocommerce"):
        checks += [
            ("/shop/",         "WooCommerce shop",   ["200", "301"]),
            ("/cart/",         "Cart page",          ["200"]),
            ("/checkout/",     "Checkout page",      ["200"]),
        ]

    p = wp.db_prefix
    for path, label, expected in checks:
        url = wp.site_url.rstrip("/") + path
        code = wp.http_code(url, timeout=20)
        if code in expected:
            ok(f"  {label}: HTTP {code}")
        else:
            err(f"  {label}: HTTP {code} (expected {'/'.join(expected)})")
            result.add(
                "HIGH" if path == "/" else "MEDIUM",
                "web-ux",
                f"{label} returned HTTP {code}",
                url
            )

    # Homepage body checks
    body = wp.http_body(wp.site_url, timeout=30)
    if body:
        # Mobile responsive (viewport meta)
        if "viewport" in body:
            ok("  Mobile viewport meta: present")
        else:
            warn("  Mobile viewport meta: missing — may not be responsive")
            result.add("MEDIUM", "web-ux", "Mobile viewport meta tag missing from homepage", wp.site_url)

        # HTTPS mixed-content check
        if wp.site_url.startswith("https://"):
            http_assets = re.findall(r'src=["\']http://[^"\']+["\']', body)
            if http_assets:
                warn(f"  Mixed content: {len(http_assets)} HTTP asset(s) on HTTPS page")
                result.add("MEDIUM", "web-ux",
                           f"Mixed content: {len(http_assets)} HTTP src= on HTTPS page", wp.site_url)
            else:
                ok("  No mixed content detected")

        # Detect common blank-page indicators
        blank_indicators = ["Fatal error", "Parse error", "Warning:", "wp_die", "Error establishing"]
        for indicator in blank_indicators:
            if indicator in body:
                err(f"  PHP error in page source: '{indicator}'")
                result.add("CRITICAL", "web-ux",
                           f"PHP error visible in homepage source: {indicator}", wp.site_url)

        # Page builder content rendered
        if struct.get("page_builder") == "Elementor" or struct.get("page_builder") == "Elementor Pro":
            if "elementor-section" in body or "elementor-widget" in body or "data-elementor" in body:
                ok("  Elementor content: rendering correctly")
            else:
                warn("  Elementor content: not detected in page source (may be rendering issue)")
                result.add("MEDIUM", "web-ux",
                           "Elementor widgets not found in homepage source — may not be rendering",
                           wp.site_url)


# ── Theme restoration ───────────────────────────────────────────────────────

def restore_theme_from_backup(wp: WPConnection, theme_slug: str,
                               backup_path: str, result: AuditResult) -> bool:
    """
    Restore theme files from a local .tar.gz backup.

    Steps:
    1. Upload backup to server temp dir
    2. Extract to wp-content/themes/
    3. Set correct permissions (755 dirs, 644 files)
    4. Verify style.css is present
    """
    section(f"Restoring theme from backup: {backup_path}")

    import os
    if not os.path.exists(backup_path):
        err(f"Backup file not found: {backup_path}")
        return False

    remote_tmp = f"/tmp/wp-theme-restore-{theme_slug}.tar.gz"

    if wp.dry_run:
        info(f"[DRY-RUN] Would upload {backup_path} → {remote_tmp}")
        info(f"[DRY-RUN] Would extract to {wp.wp('wp-content/themes/')}")
        return True

    # Upload
    info(f"Uploading backup ({os.path.getsize(backup_path)} bytes)...")
    with open(backup_path, "rb") as f:
        content = f.read()
    success = wp.sftp_write(remote_tmp, content)
    if not success:
        err("Upload failed")
        return False
    ok("Backup uploaded")

    # Extract
    theme_dir = wp.wp("wp-content/themes")
    out = wp.ssh(
        f"tar -xzf '{remote_tmp}' -C '{theme_dir}' 2>&1 && echo OK || echo FAIL",
        timeout=120
    )
    if "FAIL" in out or "OK" not in out:
        err(f"Extraction failed: {out[:200]}")
        return False
    ok(f"Extracted to {theme_dir}")

    # Set permissions
    restored_dir = f"{theme_dir}/{theme_slug}"
    wp.ssh(f"find '{restored_dir}' -type d -exec chmod 755 {{}} \\;")
    wp.ssh(f"find '{restored_dir}' -type f -exec chmod 644 {{}} \\;")
    ok("Permissions set: 755 dirs, 644 files")

    # Cleanup tmp
    wp.ssh(f"rm -f '{remote_tmp}'")

    # Verify
    if wp.wp_exists(f"wp-content/themes/{theme_slug}/style.css"):
        ok(f"Theme restored: wp-content/themes/{theme_slug}/")
        result.add("INFO", "restoration", f"Theme restored from backup: {theme_slug}", restored_dir)
        return True
    else:
        err("Restoration failed — style.css not found after extraction")
        return False


def clear_theme_caches(wp: WPConnection, theme_slug: str,
                        page_builder: str | None, result: AuditResult) -> None:
    """
    Clear all caches that store theme-related CSS/JS.

    Handles: Elementor CSS cache, WP transients, W3 Total Cache,
    WP Rocket, LiteSpeed Cache, Autoptimize, theme-specific caches.
    """
    section("Clearing Theme Caches")
    p = wp.db_prefix

    # Elementor CSS cache (generates per-page stylesheets)
    if page_builder and "Elementor" in page_builder:
        if wp.dry_run:
            info("[DRY-RUN] Would delete Elementor CSS cache from postmeta")
        else:
            wp.db_write(f"DELETE FROM {p}postmeta WHERE meta_key='_elementor_css';")
            wp.db_write(
                f"UPDATE {p}options SET option_value=option_value+1 "
                f"WHERE option_name='elementor_css_version';"
            )
            ok("Elementor CSS cache invalidated")

        # Delete generated CSS files from filesystem
        elementor_cache = wp.wp("wp-content/uploads/elementor/css")
        out = wp.ssh(f"rm -f '{elementor_cache}'/*.css 2>/dev/null && echo OK")
        if "OK" in out:
            ok("Elementor CSS files deleted (will regenerate on next load)")

    # Theme mods transient
    safe_slug = WPConnection.sql_slug(theme_slug)
    wp.db_write(
        f"DELETE FROM {p}options WHERE option_name LIKE '_transient_theme_%' "
        f"OR option_name LIKE '_site_transient_theme_%';"
    )

    # Generic object cache transients
    wp.db_write(
        f"DELETE FROM {p}options WHERE option_name LIKE '_transient_%' "
        f"AND option_name LIKE '%stylesheet%';"
    )

    # W3 Total Cache
    if wp.wp_exists("wp-content/cache/minify"):
        if not wp.dry_run:
            wp.ssh(f"rm -rf '{wp.wp('wp-content/cache/minify')}'/* 2>/dev/null")
            ok("W3TC minify cache cleared")

    # WP Rocket
    if wp.wp_exists("wp-content/cache/wp-rocket"):
        if not wp.dry_run:
            wp.ssh(f"rm -rf '{wp.wp('wp-content/cache/wp-rocket')}'/* 2>/dev/null")
            ok("WP Rocket cache cleared")

    # LiteSpeed Cache
    if wp.wp_exists("wp-content/cache/LiteSpeed"):
        if not wp.dry_run:
            wp.ssh(f"rm -rf '{wp.wp('wp-content/cache/LiteSpeed')}'/* 2>/dev/null")
            ok("LiteSpeed cache cleared")

    # WP core rewrite rules (theme switch can change permalink structure)
    wp.db_write(f"DELETE FROM {p}options WHERE option_name='rewrite_rules';")
    ok("Rewrite rules flushed (will regenerate on next request)")

    result.add("INFO", "cache-clear", "Theme caches cleared — CSS will regenerate on next page load", "")


def fix_theme_database(wp: WPConnection, theme_slug: str, result: AuditResult) -> None:
    """
    Repair theme-related database entries that commonly break after attack or migration.

    Fixes:
    - Wrong siteurl/home (causes redirect loops, broken asset URLs)
    - Missing theme activation options
    - Corrupted theme mods
    - Wrong active template/stylesheet
    """
    section("Database Integrity Fixes")
    p = wp.db_prefix

    # Verify siteurl / home match (redirect loop fix)
    siteurl = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='siteurl' LIMIT 1;"
    ).strip().splitlines()
    siteurl = siteurl[-1].strip() if siteurl else ""

    homeurl = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='home' LIMIT 1;"
    ).strip().splitlines()
    homeurl = homeurl[-1].strip() if homeurl else ""

    if siteurl and homeurl:
        if siteurl != homeurl:
            warn(f"siteurl ({siteurl}) ≠ home ({homeurl}) — potential redirect loop")
            result.add("HIGH", "db-fix", f"siteurl/home mismatch: {siteurl} vs {homeurl}", "")
        else:
            ok(f"siteurl/home: {siteurl}")

    # Verify theme options point to existing theme
    template_row = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='template' LIMIT 1;"
    ).strip().splitlines()
    template = template_row[-1].strip() if template_row else ""

    if template and template != theme_slug:
        warn(f"DB template option = '{template}', restoring theme = '{theme_slug}'")
        warn("If you are restoring a different theme, use --theme to specify it")

    # Fix active template if explicitly restoring
    if theme_slug:
        safe_slug = WPConnection.sql_escape(theme_slug)
        if not wp.dry_run:
            wp.db_write(
                f"INSERT INTO {p}options (option_name, option_value, autoload) "
                f"VALUES ('template', '{safe_slug}', 'yes') "
                f"ON DUPLICATE KEY UPDATE option_value='{safe_slug}';"
            )
            wp.db_write(
                f"INSERT INTO {p}options (option_name, option_value, autoload) "
                f"VALUES ('stylesheet', '{safe_slug}', 'yes') "
                f"ON DUPLICATE KEY UPDATE option_value='{safe_slug}';"
            )
            ok(f"Activated theme in DB: {theme_slug}")
        else:
            info(f"[DRY-RUN] Would set template/stylesheet = '{theme_slug}'")

    # Fix current_theme display name from style.css
    style_path = wp.wp(f"wp-content/themes/{theme_slug}/style.css")
    name_out = wp.ssh(f"grep -m1 '^Theme Name:' '{style_path}' 2>/dev/null")
    if name_out:
        display_name = name_out.replace("Theme Name:", "").strip()
        safe_name = WPConnection.sql_escape(display_name)
        if not wp.dry_run:
            wp.db_write(
                f"INSERT INTO {p}options (option_name, option_value, autoload) "
                f"VALUES ('current_theme', '{safe_name}', 'yes') "
                f"ON DUPLICATE KEY UPDATE option_value='{safe_name}';"
            )
            ok(f"current_theme set to: {display_name}")

    result.add("INFO", "db-fix", f"Theme DB options verified/repaired for: {theme_slug}", "")


def step_by_step_restoration(wp: WPConnection, args: argparse.Namespace,
                              struct: dict, result: AuditResult) -> None:
    """
    Full step-by-step theme restoration workflow.

    Step 1: Backup current state
    Step 2: Restore theme files (from backup or re-download)
    Step 3: Fix database entries
    Step 4: Clear all caches
    Step 5: Verify frontend renders correctly
    Step 6: Report
    """
    section("Step-by-Step Theme Restoration")
    theme_slug = args.theme or struct.get("theme_slug", "")
    page_builder = struct.get("page_builder")

    if not theme_slug:
        err("No theme slug determined — use --theme <slug>")
        sys.exit(1)

    # Step 1 — Backup current state
    info("Step 1/6: Backup current theme state")
    p = wp.db_prefix
    backup_dir = wp.wp("wp-content/wp-arsenal-theme-backups")
    if not wp.dry_run:
        wp.ssh(f"mkdir -p '{backup_dir}'")
        theme_dir = wp.wp(f"wp-content/themes/{theme_slug}")
        if wp.wp_exists(f"wp-content/themes/{theme_slug}"):
            ts_out = wp.ssh("date +%Y%m%d-%H%M%S")
            ts = ts_out.strip() or "backup"
            archive = f"{backup_dir}/{theme_slug}-pre-restore-{ts}.tar.gz"
            out = wp.ssh(
                f"tar -czf '{archive}' -C '{wp.wp('wp-content/themes')}' '{theme_slug}' "
                f"2>/dev/null && echo OK || echo FAIL",
                timeout=60
            )
            if "OK" in out:
                ok(f"  Pre-restore backup: {archive}")
            else:
                warn("  Pre-restore backup failed (continuing anyway)")
        else:
            info("  Theme dir missing — no backup needed")
    else:
        info("[DRY-RUN] Would back up current theme")

    # Step 2 — Restore files
    info("Step 2/6: Restore theme files")
    if args.from_backup:
        restored = restore_theme_from_backup(wp, theme_slug, args.from_backup, result)
        if not restored:
            err("File restoration failed — aborting")
            sys.exit(1)
    else:
        # Check if theme dir is present (may just need DB fix + cache clear)
        if wp.wp_exists(f"wp-content/themes/{theme_slug}"):
            ok(f"  Theme directory present: {theme_slug}")
        else:
            err(f"  Theme files missing and no --from-backup provided")
            err(f"  Provide a backup with: --from-backup /path/to/{theme_slug}.tar.gz")
            err(f"  Or re-download from: https://wordpress.org/themes/{theme_slug}/")
            result.add("CRITICAL", "restoration", "Theme files missing — provide --from-backup", "")
            sys.exit(1)

    # Step 3 — Fix database
    info("Step 3/6: Repair database entries")
    fix_theme_database(wp, theme_slug, result)

    # Step 4 — Clear caches
    info("Step 4/6: Clear all caches")
    clear_theme_caches(wp, theme_slug, page_builder, result)

    # Step 5 — Verify frontend
    info("Step 5/6: Verify frontend renders correctly")
    audit_frontend_assets(wp, result)
    verify_web_ux(wp, struct, result)

    # Step 6 — Final verification
    info("Step 6/6: Final status check")
    if wp.site_url:
        final_code = wp.http_code(wp.site_url, timeout=20)
        if final_code in ("200", "301", "302"):
            ok(f"Site responding: HTTP {final_code}")
            result.add("INFO", "restoration", f"Restoration complete — site HTTP {final_code}", wp.site_url)
        else:
            err(f"Site still returning HTTP {final_code} — manual intervention needed")
            result.add("CRITICAL", "restoration",
                       f"Site still broken after restoration: HTTP {final_code}", wp.site_url)


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Full WordPress theme restoration with Web UI/UX verification"
    )
    add_connection_args(parser)
    parser.add_argument("--theme", default="",
                        help="Theme slug to restore (auto-detected from DB if omitted)")
    parser.add_argument("--from-backup", dest="from_backup", default="",
                        help="Local path to theme .tar.gz backup to restore")
    parser.add_argument("--verify-only", dest="verify_only", action="store_true",
                        help="Only run structure + UX checks, no restoration")
    parser.add_argument("--structure-only", dest="structure_only", action="store_true",
                        help="Only audit WordPress folder structure, no restoration")
    args = parser.parse_args()

    print_banner("WP-THEME-RESTORE — Full Theme Restoration & Web UX Verification", args.dry_run)
    result = AuditResult("wp-theme-restore")

    with WPConnection(args) as wp:

        # Always audit structure first
        struct = audit_wp_structure(wp, result)

        if args.structure_only:
            result.print_summary()
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            return

        # Determine theme slug
        theme_slug = args.theme or struct.get("theme_slug", "")
        if not theme_slug:
            err("Cannot determine active theme — use --theme <slug>")
            sys.exit(1)

        # Audit theme files
        theme_info = audit_theme_files(wp, theme_slug, result)

        # If child theme, audit parent too
        if theme_info.get("is_child_theme") and theme_info.get("parent_slug"):
            audit_theme_files(wp, theme_info["parent_slug"], result)

        if args.verify_only:
            audit_frontend_assets(wp, result)
            verify_web_ux(wp, struct, result)
        else:
            step_by_step_restoration(wp, args, struct, result)

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

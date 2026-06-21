#!/usr/bin/env python3
"""
wp-child-theme.py — Scaffold and deploy a WordPress child theme via SSH
=======================================================================
Creates a properly structured child theme for any parent theme and uploads
it to the server. Handles enqueueing parent styles correctly (the right way,
not @import in style.css). Supports Kadence, Astra, GeneratePress, Hello
Elementor, OceanWP, and any custom parent by slug.

Usage:
  python scripts/management/wp-child-theme.py --config config/config.yaml \
      --parent kadence --child-name "My Kadence Child"

  python scripts/management/wp-child-theme.py --config config/config.yaml \
      --parent astra --child-name "Client Site Theme" --activate

  python scripts/management/wp-child-theme.py --config config/config.yaml \
      --list-parents

  python scripts/management/wp-child-theme.py --config config/config.yaml \
      --parent hello-elementor --child-name "Elementor Child" \
      --child-slug my-elementor-child --activate
"""

import argparse
import json
import os
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

# Known parent themes — slug → display name
KNOWN_PARENTS = {
    "kadence":          "Kadence",
    "astra":            "Astra",
    "generatepress":    "GeneratePress",
    "hello-elementor":  "Hello Elementor",
    "oceanwp":          "OceanWP",
    "blocksy":          "Blocksy",
    "neve":             "Neve",
    "divi":             "Divi",
    "avada":            "Avada",
    "enfold":           "Enfold",
    "twentytwentyfour": "Twenty Twenty-Four",
    "twentytwentythree": "Twenty Twenty-Three",
    "twentytwentytwo":  "Twenty Twenty-Two",
}

# Parents that load their own styles differently — need special enqueueing
PARENTS_WITH_CUSTOM_ENQUEUE = {
    "divi", "avada", "enfold",  # these frameworks manage their own styles
}


def get_parent_display_name(wp: WPConnection, parent_slug: str) -> str:
    """Read Theme Name from parent's style.css."""
    style_css = wp.wp(f"wp-content/themes/{parent_slug}/style.css")
    out = wp.ssh(
        f"grep -m 1 '^Theme Name:' {shlex.quote(style_css)} 2>/dev/null"
    )
    if out.strip():
        return out.strip().replace("Theme Name:", "").strip()
    return KNOWN_PARENTS.get(parent_slug, parent_slug.replace("-", " ").title())


def get_parent_version(wp: WPConnection, parent_slug: str) -> str:
    """Read Version from parent's style.css."""
    style_css = wp.wp(f"wp-content/themes/{parent_slug}/style.css")
    out = wp.ssh(
        f"grep -m 1 '^Version:' {shlex.quote(style_css)} 2>/dev/null"
    )
    if out.strip():
        return out.strip().replace("Version:", "").strip()
    return "1.0"


def generate_style_css(
    child_name: str,
    child_slug: str,
    parent_slug: str,
    parent_display: str,
    author: str,
    description: str,
    version: str,
) -> str:
    return f"""/*
Theme Name:   {child_name}
Theme URI:    https://example.com
Description:  Child theme for {parent_display}. {description}
Author:       {author}
Author URI:   https://example.com
Template:     {parent_slug}
Version:      {version}
License:      GNU General Public License v2 or later
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
Text Domain:  {child_slug}
*/
"""


def generate_functions_php(
    child_slug: str,
    parent_slug: str,
    child_name: str,
    is_elementor_parent: bool,
    is_custom_enqueue_parent: bool,
) -> str:
    if is_elementor_parent:
        # Hello Elementor — parent handles styles, minimal child functions.php
        enqueue_block = f"""/**
 * Enqueue child theme styles.
 * Hello Elementor handles parent styles — we only add child-specific styles.
 */
function {child_slug.replace('-', '_')}_enqueue_styles() {{
    $parent_version = wp_get_theme( get_template() )->get( 'Version' );
    wp_enqueue_style(
        'hello-elementor-style',
        get_template_directory_uri() . '/style.css',
        array(),
        $parent_version
    );
    wp_enqueue_style(
        '{child_slug}-style',
        get_stylesheet_directory_uri() . '/style.css',
        array( 'hello-elementor-style' ),
        wp_get_theme()->get( 'Version' )
    );
}}
add_action( 'wp_enqueue_scripts', '{child_slug.replace('-', '_')}_enqueue_styles' );
"""
    elif is_custom_enqueue_parent:
        # Divi, Avada etc. — don't override their style system
        enqueue_block = f"""/**
 * Note: {parent_slug} manages its own styles.
 * Add child-specific styles below without overriding parent.
 */
function {child_slug.replace('-', '_')}_enqueue_styles() {{
    wp_enqueue_style(
        '{child_slug}-style',
        get_stylesheet_directory_uri() . '/style.css',
        array(),
        wp_get_theme()->get( 'Version' )
    );
}}
add_action( 'wp_enqueue_scripts', '{child_slug.replace('-', '_')}_enqueue_styles' );
"""
    else:
        # Standard child theme — enqueue parent style first, then child
        enqueue_block = f"""/**
 * Enqueue parent and child theme styles.
 * Using wp_enqueue_scripts (NOT @import in style.css — that's the wrong way).
 */
function {child_slug.replace('-', '_')}_enqueue_styles() {{
    $parent_style = '{parent_slug}-style';
    $parent_version = wp_get_theme( get_template() )->get( 'Version' );

    wp_enqueue_style(
        $parent_style,
        get_template_directory_uri() . '/style.css',
        array(),
        $parent_version
    );
    wp_enqueue_style(
        '{child_slug}-style',
        get_stylesheet_directory_uri() . '/style.css',
        array( $parent_style ),
        wp_get_theme()->get( 'Version' )
    );
}}
add_action( 'wp_enqueue_scripts', '{child_slug.replace('-', '_')}_enqueue_styles' );
"""

    return f"""<?php
/**
 * {child_name} — Child theme functions
 *
 * Add your custom functions, hooks, and filters here.
 * This file is loaded after the parent theme's functions.php.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

{enqueue_block}

// ── Add your customisations below ─────────────────────────────────────────

"""


def generate_index_php() -> str:
    return "<?php\n// Silence is golden.\n"


def activate_theme(wp: WPConnection, child_slug: str, result: AuditResult) -> None:
    """Activate the child theme by updating template and stylesheet DB options."""
    p = wp.db_prefix
    child_slug = WPConnection.sql_slug(child_slug)
    if wp.dry_run:
        info(f"[DRY-RUN] Would activate theme: {child_slug}")
        return
    wp.db_write(
        f"UPDATE {p}options SET option_value='{child_slug}' "
        f"WHERE option_name='template' OR option_name='stylesheet' OR option_name='current_theme';"
    )
    # Clear theme-related transients
    wp.db_write(
        f"DELETE FROM {p}options WHERE option_name LIKE '_transient_theme_%' "
        f"OR option_name LIKE '_site_transient_theme_%';"
    )
    ok(f"Theme activated: {child_slug}")
    result.add("INFO", "theme-activated", f"Child theme activated: {child_slug}", "")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Scaffold and deploy a WordPress child theme"
    )
    add_connection_args(parser)
    parser.add_argument("--parent", default="",
                        help="Parent theme slug (e.g. kadence, astra, hello-elementor)")
    parser.add_argument("--child-name", dest="child_name", default="",
                        help="Display name for the child theme")
    parser.add_argument("--child-slug", dest="child_slug", default="",
                        help="Directory name for child theme (default: parent-slug-child)")
    parser.add_argument("--author", default="",
                        help="Theme author name")
    parser.add_argument("--description", default="",
                        help="Theme description")
    parser.add_argument("--version", default="1.0.0",
                        help="Theme version (default: 1.0.0)")
    parser.add_argument("--activate", action="store_true",
                        help="Activate the child theme after deployment")
    parser.add_argument("--list-parents", action="store_true",
                        help="List installed themes (valid parents) and exit")
    args = parser.parse_args()

    print_banner("WP-CHILD-THEME — Child Theme Scaffolder", args.dry_run)
    result = AuditResult("wp-child-theme")

    with WPConnection(args) as wp:

        if args.list_parents:
            section("Installed themes (valid parents)")
            out = wp.ssh(
                f"ls -1 {shlex.quote(wp.wp('wp-content/themes'))} 2>/dev/null"
            )
            active = wp.db(
                f"SELECT option_value FROM {wp.db_prefix}options WHERE option_name='template' LIMIT 1;"
            ).strip().splitlines()[-1].strip() if wp.db_prefix else ""

            for theme in sorted(t.strip() for t in out.splitlines() if t.strip()):
                name = get_parent_display_name(wp, theme)
                ver  = get_parent_version(wp, theme)
                mark = " ← active" if theme == active else ""
                info(f"  {theme:30}  {name:30}  v{ver}{mark}")
            return

        if not args.parent:
            err("--parent is required. Use --list-parents to see available themes.")
            sys.exit(1)

        try:
            parent_slug = WPConnection.sql_slug(args.parent)
            child_slug  = WPConnection.sql_slug(args.child_slug or f"{args.parent}-child")
        except ValueError as exc:
            err(str(exc))
            sys.exit(1)
        child_name = args.child_name or f"{parent_slug.replace('-', ' ').title()} Child"
        author         = args.author or "Site Owner"
        description    = args.description or f"Child theme for {parent_slug}"
        is_elementor   = parent_slug == "hello-elementor"
        is_custom_enq  = parent_slug in PARENTS_WITH_CUSTOM_ENQUEUE

        section(f"Parent theme: {parent_slug}")
        if not wp.wp_exists(f"wp-content/themes/{parent_slug}"):
            err(f"Parent theme '{parent_slug}' not found on server")
            err(f"Run --list-parents to see available themes")
            sys.exit(1)

        parent_display = get_parent_display_name(wp, parent_slug)
        parent_version = get_parent_version(wp, parent_slug)
        ok(f"Parent: {parent_display} v{parent_version}")

        child_dir = wp.wp(f"wp-content/themes/{child_slug}")

        if wp.wp_exists(f"wp-content/themes/{child_slug}"):
            warn(f"Child theme directory already exists: {child_dir}")
            warn("Overwriting existing files")

        section(f"Creating child theme: {child_name} ({child_slug})")

        # Generate file contents
        style_content     = generate_style_css(child_name, child_slug, parent_slug,
                                               parent_display, author, description, args.version)
        functions_content = generate_functions_php(child_slug, parent_slug, child_name,
                                                   is_elementor, is_custom_enq)
        index_content     = generate_index_php()

        if wp.dry_run:
            info("[DRY-RUN] Would create:")
            info(f"  {child_dir}/style.css")
            info(f"  {child_dir}/functions.php")
            info(f"  {child_dir}/index.php")
            if args.activate:
                info(f"  Would activate theme: {child_slug}")
            result.print_summary()
            return

        # Create directory and upload files
        wp.ssh(f"mkdir -p {shlex.quote(child_dir)}")

        wp.sftp_write(f"{child_dir}/style.css",     style_content.encode())
        ok(f"  Created style.css")

        wp.sftp_write(f"{child_dir}/functions.php", functions_content.encode())
        ok(f"  Created functions.php")

        wp.sftp_write(f"{child_dir}/index.php",     index_content.encode())
        ok(f"  Created index.php")

        # Fix permissions
        wp.ssh(f"chmod 755 {shlex.quote(child_dir)}")
        wp.ssh(
            f"chmod 644 {shlex.quote(child_dir + '/style.css')} "
            f"{shlex.quote(child_dir + '/functions.php')} "
            f"{shlex.quote(child_dir + '/index.php')}"
        )
        ok(f"  Permissions set (755 dir, 644 files)")

        result.add("INFO", "theme-created", f"Child theme created: {child_slug}", child_dir)
        result.stat("child_slug", child_slug)
        result.stat("parent_slug", parent_slug)
        result.stat("theme_dir", child_dir)

        info(f"\n  Next steps:")
        info(f"  1. Go to WP Admin → Appearance → Themes")
        info(f"  2. Activate '{child_name}'")
        info(f"  3. Add your custom CSS to: {child_dir}/style.css")
        info(f"  4. Add your custom PHP to: {child_dir}/functions.php")

        if args.activate:
            section("Activating child theme")
            activate_theme(wp, child_slug, result)
            # Verify site still responds
            if wp.site_url:
                code = wp.http_code(wp.site_url, timeout=15)
                if code == 200:
                    ok(f"Site responds HTTP {code} with child theme active")
                else:
                    err(f"Site returned HTTP {code} after activation — check theme")
                    result.add("HIGH", "activation-error",
                               f"Site returned HTTP {code} after activating {child_slug}", "")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

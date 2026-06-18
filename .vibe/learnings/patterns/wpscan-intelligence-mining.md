---
name: wpscan-intelligence-mining
description: Mining WPScan/Wordpresscan source for detection patterns we can port — 36 wp-config backup variants, 5-dir listing checks, REST API enum
metadata:
  type: project
---

## Pattern: Mine Established Security Tools for Detection Logic

### What Worked
Reading WPScan's Ruby finder modules (19 modules) and Wordpresscan's Python engine revealed concrete detection gaps:

| Source | Finding | Impact |
|--------|---------|--------|
| Wordpresscan | 36 `wp-config.php` backup filename variants (we had 5) | 31 new detection paths |
| Wordpresscan | `/wp-json/wp/v2/users` — zero-auth REST API user enum | New HIGH finding class |
| WPScan | Directory listing on all 5 WP dirs (`uploads/`, `plugins/`, `themes/`, `includes/`, `admin/`) | 4 new checks |
| WPScan | `wp-content/uploads/dump.sql` — SQL dump in public uploads | CRITICAL detection |
| WPScan | `emergency.php`, `searchreplacedb2.php` in webroot | CRITICAL detection |
| WPScan | `readme.html` version disclosure | MEDIUM detection |
| WPScan | `robots.txt` Disallow path parsing | LOW detection |
| SlickStack | MyISAM→InnoDB conversion, staging table cleanup | DB optimization ideas |

### How to Mine
```
gh api repos/OWNER/REPO/contents/PATH --jq '.content' | \
  powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($input -join '')))"
```

### When to Use
After any significant new detection feature: spend 30 min reading the equivalent
detection in WPScan (Ruby), WPSeku, Wordpresscan (Python), or OWASP ZAP rules.
The patterns are public domain and represent years of accumulated attacker knowledge.

**Why:** Security tools converge on the same attacker patterns. If WPScan checks for
something, it's because real attackers did it often enough to matter. We get their
research for free.

**How to apply:**
1. `gh search repos "[feature] wordpress scanner" --sort stars --limit 10`
2. Read the detection module source (not README)
3. Port the check pattern, not the framework

#!/usr/bin/env python3
"""
GitHub PR webhook handler for wp-arsenal.

Receives PR events and triggers automated review pipeline.
Deploy as a serverless function or behind a reverse proxy.

Usage:
    python scripts/pr-webhook.py [--port 8080] [--secret YOUR_WEBHOOK_SECRET]

Events handled:
    - pull_request.opened → run full review pipeline
    - pull_request.synchronize → re-run review on new commits
    - pull_request_review.submitted → log review, check approvals
    - issue_comment.created → check for /review, /approve, /reject commands
"""

import hmac
import hashlib
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from typing import Dict, Any

WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
REPO = "rahlplx/wp-arsenal"


def verify_signature(payload: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        return True
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_pr_opened(event: Dict[str, Any]) -> Dict[str, Any]:
    pr = event["pull_request"]
    return {
        "action": "review_triggered",
        "pr_number": pr["number"],
        "pr_title": pr["title"],
        "branch": pr["head"]["ref"],
        "base": pr["base"]["ref"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": [
            "test_suite",
            "harness",
            "security_audit",
            "code_review",
        ],
    }


def handle_pr_synchronize(event: Dict[str, Any]) -> Dict[str, Any]:
    pr = event["pull_request"]
    return {
        "action": "re_review_triggered",
        "pr_number": pr["number"],
        "commits_ahead": pr["commits"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def handle_review_submitted(event: Dict[str, Any]) -> Dict[str, Any]:
    review = event["review"]
    return {
        "action": "review_logged",
        "state": review["state"],
        "author": review["user"]["login"],
        "pr_number": event["pull_request"]["number"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def handle_issue_comment(event: Dict[str, Any]) -> Dict[str, Any]:
    comment = event["comment"]["body"].strip().lower()
    pr_number = event["issue"]["number"]

    commands = {
        "/review": "full_review",
        "/approve": "approve_pr",
        "/reject": "reject_pr",
        "/harness": "run_harness",
        "/tests": "run_tests",
    }

    for cmd, action in commands.items():
        if comment.startswith(cmd):
            return {
                "action": action,
                "pr_number": pr_number,
                "author": event["comment"]["user"]["login"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    return {"action": "no_command", "pr_number": pr_number}


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)

        signature = self.headers.get("X-Hub-Signature-256", "")
        if not verify_signature(payload, signature):
            self.send_response(401)
            self.end_headers()
            return

        event_type = self.headers.get("X-GitHub-Event", "")
        event = json.loads(payload)

        handlers = {
            "pull_request": lambda e: (
                handle_pr_opened(e) if e["action"] == "opened"
                else handle_pr_synchronize(e) if e["action"] == "synchronize"
                else {"action": "ignored", "reason": e["action"]}
            ),
            "pull_request_review": handle_review_submitted,
            "issue_comment": handle_issue_comment,
        }

        handler = handlers.get(event_type)
        if handler:
            result = handler(event)
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps({"action": "unknown_event", "type": event_type}))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode())

    def log_message(self, format, *args):
        print(f"[{datetime.now(timezone.utc).isoformat()}] {args[0]}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    print(f"Webhook server running on port {port}")
    print(f"Events: pull_request, pull_request_review, issue_comment")
    print(f"Commands: /review, /approve, /reject, /harness, /tests")
    server.serve_forever()


if __name__ == "__main__":
    main()

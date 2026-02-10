#!/usr/bin/env python3
"""
Sanity checks for response-based success criteria (binary 1/0).
Uses representative payloads from attack_success_criteria.docx.
"""
from response_heuristics import evaluate_response


def make_entry(url: str, body: str, status: int = 200, headers: dict | None = None, duration_ms: int | None = None):
    return {
        "request": {
            "method": "GET",
            "url": url,
            "path": url,
            "body": "",
        },
        "response": {
            "status_code": status,
            "body": body,
            "headers": headers or {},
        },
        "duration_ms": duration_ms,
    }


TESTS = [
    # SQLi
    ("sqli", make_entry("/api/products/search?q=' UNION SELECT 1,2--", "SQLITE_ERROR: near \"UNION\": syntax error"), True),
    ("sqli", make_entry("/api/products/search?q=sleep(5)", "ok", status=200, duration_ms=5100), True),
    ("sqli", make_entry("/api/products/search?q='", "invalid sql syntax", status=400), False),
    ("sqli", make_entry("/api/products/search?q=' OR 1=1--", "SQLITE_ERROR: ... WAF block detected", status=200), False),

    # XSS
    ("xss", make_entry("/search?q=<script>alert(1)</script>", "<html><body><script>alert(1)</script></body></html>"), True),
    ("xss", make_entry("/search?q=<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;", status=200), False),

    # IDOR
    ("idor", make_entry("/api/users/2", '{"id":2,"email":"victim@site.com","address":"x"}'), True),
    ("idor", make_entry("/api/users/2", "Access denied", status=403), False),

    # Auth bypass
    ("auth_bypass", make_entry("/api/login", '{"token":"abc123","role":"admin"}', status=200), True),
    ("auth_bypass", make_entry("/api/login", "Unauthorized", status=401), False),

    # Path Traversal
    ("path_traversal", make_entry("/api/file?path=../../etc/passwd", "root:x:0:0:root:/root:/bin/bash"), True),
    ("path_traversal", make_entry("/api/file?path=../../etc/passwd", "Access denied", status=403), False),

    # SSRF
    ("ssrf", make_entry("/api/fetch?url=http://169.254.169.254/latest/meta-data/", "instance-id\nami-id\n"), True),
    ("ssrf", make_entry("/api/fetch?url=bad://", "Invalid URL", status=400), False),

    # CMDi
    ("cmdi", make_entry("/api/diagnostic?host=127.0.0.1;id", "uid=0(root) gid=0(root) groups=0(root)"), True),
    ("cmdi", make_entry("/api/diagnostic?host=127.0.0.1;id", "command not found", status=200), False),

    # CSRF
    ("csrf", make_entry("/api/transfer", "Transfer completed", status=200), True),
    ("csrf", make_entry("/api/transfer", "CSRF token invalid", status=403), False),

    # File Upload
    ("file_upload", make_entry("/api/upload", '{"uploaded":true,"file_url":"/uploads/shell.php"}', status=200), True),
    ("file_upload", make_entry("/api/upload", "File type not allowed", status=415), False),

    # Info Disclosure
    ("info_disclosure", make_entry("/debug", "DB_PASSWORD=secret\nAPI_KEY=abc"), True),
    ("info_disclosure", make_entry("/.env", "<html>404 not found</html>", status=404), False),
]


def main() -> int:
    passed = 0
    failed = 0
    for family, entry, expected in TESTS:
        result = evaluate_response(entry, family)
        ok = result["success"] == expected
        if ok:
            passed += 1
        else:
            failed += 1
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {family:16} expected={expected} got={result['success']} evidence={result['evidence']}")

    print(f"\nSummary: {passed} passed, {failed} failed, {len(TESTS)} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

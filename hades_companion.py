"""Local authenticated companion API for the Hades browser extension."""
import argparse
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from flask import Flask, Response, jsonify, request
from authorization_verifier import (
    AuditLogEntry, AuthorizationDatabase, AuthorizationRecord
)
from hades_headless_modules import HeadlessModuleBridge

HOST, PORT = "127.0.0.1", 8765


def normalize_origin(value):
    """Return a canonical HTTP(S) origin and reject ambiguous URLs."""
    try:
        parsed = urlsplit((value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("Target must be a valid HTTP or HTTPS URL") from None
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default = 80 if parsed.scheme == "http" else 443
    return f"{parsed.scheme}://{host}{f':{port}' if port not in (None, default) else ''}"


class ScanStore:
    def __init__(self, path):
        self.path = path
        with closing(self.connect()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS passive_scans
                (id TEXT PRIMARY KEY, created_at TEXT, target_origin TEXT,
                 page_url TEXT, page_title TEXT, findings_json TEXT)""")
            db.commit()

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def save(self, origin, page, findings):
        scan_id, created = uuid4().hex, datetime.now(timezone.utc).isoformat()
        with closing(self.connect()) as db:
            db.execute("INSERT INTO passive_scans VALUES (?, ?, ?, ?, ?, ?)",
                       (scan_id, created, origin, page.get("url", "")[:4000],
                        str(page.get("title") or "")[:500], json.dumps(findings)))
            db.commit()
        return self.get(scan_id)

    def get(self, scan_id):
        with closing(self.connect()) as db:
            row = db.execute("SELECT * FROM passive_scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["findings"] = json.loads(result.pop("findings_json"))
        return result

    def list(self):
        with closing(self.connect()) as db:
            rows = db.execute("SELECT * FROM passive_scans ORDER BY created_at DESC LIMIT 25").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["findings"] = json.loads(item.pop("findings_json"))
            result.append(item)
        return result


def analyze_page(page):
    """Generate conservative findings from active-tab DOM metadata."""
    findings, url = [], page.get("url", "")
    parsed = urlsplit(url)
    meta = {str(k).lower(): str(v) for k, v in (page.get("metaHeaders") or {}).items()}

    def add(rule_id, title, severity, evidence, remediation):
        findings.append({"id": rule_id, "title": title, "severity": severity,
                         "confidence": "observed", "evidence": evidence,
                         "remediation": remediation})

    if parsed.scheme == "http":
        add("transport-http", "Page uses unencrypted HTTP", "high", url,
            "Serve the application over HTTPS and redirect HTTP requests.")
    mixed = list(page.get("mixedContent") or [])[:20]
    if mixed:
        add("mixed-content", "HTTPS page references HTTP resources", "medium",
            f"{len(mixed)} resource(s), including {mixed[0]}",
            "Load every resource and form action over HTTPS.")
    insecure_forms = [f for f in (page.get("forms") or [])
                      if str(f.get("action", "")).startswith("http://")]
    if insecure_forms:
        add("insecure-form-action", "Form submits over HTTP", "high",
            f"{len(insecure_forms)} form(s) submit to an unencrypted endpoint.",
            "Use an HTTPS action URL for every form.")
    if page.get("passwordFormsOnHttp"):
        add("password-over-http", "Password field is presented over HTTP", "critical",
            "A password input is present on an unencrypted page.",
            "Move authentication entirely to HTTPS and enable HSTS.")
    if parsed.scheme == "https" and not meta.get("content-security-policy"):
        add("csp-not-observed", "Content Security Policy was not observed", "info",
            "No CSP meta element was found; response headers are not visible to DOM analysis.",
            "Verify the HTTP response sets an appropriate Content-Security-Policy header.")
    if page.get("targetBlankWithoutNoopener"):
        add("unsafe-target-blank", "New-tab links lack opener isolation", "low",
            f"{page['targetBlankWithoutNoopener']} target=_blank link(s) lack rel=noopener.",
            'Add rel="noopener noreferrer" to external target=_blank links.')
    return findings


def markdown_report(scan):
    lines = ["# Hades AI Passive Security Report", "", f"- Target: {scan['page_url']}",
             f"- Created: {scan['created_at']}", f"- Findings: {len(scan['findings'])}", "",
             "> Passive browser analysis only. Validate observations against server response headers.", ""]
    if not scan["findings"]:
        lines.append("No issues were observed by the passive checks.")
    for finding in scan["findings"]:
        lines += [f"## [{finding['severity'].upper()}] {finding['title']}", "",
                  f"**Evidence:** {finding['evidence']}", "",
                  f"**Remediation:** {finding['remediation']}", ""]
    return "\n".join(lines)


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=1_000_000,
                      TOKEN_PATH=str(Path.home() / ".hades_companion_token"),
                      DATABASE_PATH=str(Path.home() / ".hades_companion.db"),
                      AUTH_DATABASE_PATH=str(Path.home() / ".hades_authorizations.db"))
    app.config.update(config or {})
    token_path = Path(app.config["TOKEN_PATH"])
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token = token_path.read_text(encoding="utf-8").strip() if token_path.exists() else ""
    if not token:
        token = secrets.token_urlsafe(32)
        token_path.write_text(token, encoding="utf-8")
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
    app.config["COMPANION_TOKEN"] = token
    app.extensions["scans"] = ScanStore(app.config["DATABASE_PATH"])
    # The legacy store owns a sqlite connection, so use one short-lived instance
    # per operation instead of sharing it across Flask request threads.
    def auth_call(method, *args):
        database = AuthorizationDatabase(app.config["AUTH_DATABASE_PATH"])
        try:
            return getattr(database, method)(*args)
        finally:
            database.conn.close()

    app.extensions["conversations"] = None
    app.extensions["modules"] = HeadlessModuleBridge(app.config.get("MODULE_DATA_ROOT"))

    @app.after_request
    def extension_headers(response):
        origin = request.headers.get("Origin", "")
        if origin.startswith("chrome-extension://"):
            response.headers.update({"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                                     "Access-Control-Allow-Headers": "Authorization, Content-Type",
                                     "Access-Control-Allow-Methods": "GET, POST, OPTIONS"})
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def options():
        return Response(status=204) if request.method == "OPTIONS" else None

    def protected(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            expected = f"Bearer {app.config['COMPANION_TOKEN']}"
            if not hmac.compare_digest(request.headers.get("Authorization", ""), expected):
                return jsonify(error="Invalid or missing companion token"), 401
            return function(*args, **kwargs)
        return wrapped

    def authorized(page):
        origin = normalize_origin(page.get("url", ""))
        allowed, record = auth_call("is_authorized", origin)
        if not allowed:
            return None, (jsonify(error=f"Target is not authorized: {origin}"), 403)
        return (origin, record), None

    @app.get("/api/v1/health")
    def health():
        return jsonify(status="ok", service="hades-companion", version=3)

    @app.get("/api/v1/session")
    @protected
    def session():
        return jsonify(authenticated=True, companion_version=3)

    @app.get("/api/v1/authorizations")
    @protected
    def authorizations():
        records = auth_call("get_authorizations")
        for record in records:
            record["approved"] = auth_call("is_authorized", record["target_url"])[0]
        return jsonify(authorizations=records)

    @app.post("/api/v1/authorizations")
    @protected
    def authorize():
        data = request.get_json(silent=True) or {}
        if data.get("acknowledged") is not True:
            return jsonify(error="Explicit authorization acknowledgement is required"), 400
        owner = str(data.get("authorized_by", "")).strip()
        if not owner:
            return jsonify(error="authorized_by is required"), 400
        scope = str(data.get("scope") or "passive_browser_assessment")
        if scope not in {"passive_browser_assessment", "active_web_assessment"}:
            return jsonify(error="Unsupported assessment scope"), 400
        try:
            origin = normalize_origin(data.get("target_url", ""))
            expiration = data.get("expiration_date") or None
            if expiration:
                expiry = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
                if expiry.tzinfo:
                    expiry = expiry.astimezone().replace(tzinfo=None)
                expiration = expiry.isoformat()
        except ValueError as error:
            return jsonify(error=str(error)), 400
        record = AuthorizationRecord(origin, urlsplit(origin).hostname or "", owner[:200],
                                     datetime.now().isoformat(),
                                     "browser_extension_acknowledgement",
                                     scope,
                                     expiration, str(data.get("notes") or "")[:1000], True)
        record_id = auth_call("add_authorization", record)
        return jsonify(id=record_id, target_origin=origin), 201

    @app.get("/api/v1/audit")
    @protected
    def audit_history():
        return jsonify(events=auth_call("get_test_history", None, 100))

    @app.post("/api/v1/authorizations/revoke")
    @protected
    def revoke():
        try:
            origin = normalize_origin((request.get_json(silent=True) or {}).get("target_url", ""))
        except ValueError as error:
            return jsonify(error=str(error)), 400
        auth_call("revoke_authorization", origin)
        return jsonify(revoked=True, target_origin=origin)

    @app.post("/api/v1/analyze")
    @protected
    def analyze():
        page = request.get_json(silent=True) or {}
        try:
            authorization, error = authorized(page)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        return jsonify(app.extensions["scans"].save(authorization[0], page, analyze_page(page))), 201

    @app.get("/api/v1/scans")
    @protected
    def scans():
        return jsonify(scans=app.extensions["scans"].list())

    @app.get("/api/v1/scans/<scan_id>/report")
    @protected
    def report(scan_id):
        scan = app.extensions["scans"].get(scan_id)
        if not scan:
            return jsonify(error="Scan not found"), 404
        return Response(markdown_report(scan), content_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="hades-report-{scan_id[:8]}.md"'})

    @app.get("/api/v1/modules")
    @protected
    def modules():
        return jsonify(modules=app.extensions["modules"].capabilities())

    @app.post("/api/v1/modules/knowledge/search")
    @protected
    def search_knowledge():
        data = request.get_json(silent=True) or {}
        try:
            _authorization, error = authorized(data.get("page") or {})
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        query = str(data.get("query") or "").strip()
        if not query:
            return jsonify(error="query is required"), 400
        return jsonify(app.extensions["modules"].search_knowledge(query[:200]))

    @app.get("/api/v1/modules/cache")
    @protected
    def cache_module():
        return jsonify(app.extensions["modules"].cache_summary())

    @app.post("/api/v1/modules/payloads")
    @protected
    def payload_module():
        data = request.get_json(silent=True) or {}
        try:
            authorization, error = authorized(data.get("page") or {})
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        if authorization[1].scope != "active_web_assessment":
            return jsonify(error="Payload tools require active_web_assessment authorization"), 403
        vulnerability_type = str(data.get("vulnerability_type") or "").strip()
        if not vulnerability_type:
            return jsonify(error="vulnerability_type is required"), 400
        return jsonify(payloads=app.extensions["modules"].payload_catalog(vulnerability_type)[:50])

    @app.post("/api/v1/modules/mutations")
    @protected
    def mutation_module():
        data = request.get_json(silent=True) or {}
        try:
            authorization, error = authorized(data.get("page") or {})
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        if authorization[1].scope != "active_web_assessment":
            return jsonify(error="Payload tools require active_web_assessment authorization"), 403
        payload = str(data.get("payload") or "")
        if not payload or len(payload) > 4000:
            return jsonify(error="payload must contain 1-4000 characters"), 400
        mutations = app.extensions["modules"].mutate_payload(
            payload, str(data.get("technology") or "") or None,
            str(data.get("target_waf") or "") or None, 10)
        return jsonify(mutations=mutations)

    @app.post("/api/v1/modules/validate")
    @protected
    def validation_module():
        data = request.get_json(silent=True) or {}
        page = data.get("page") or {}
        try:
            authorization, error = authorized(page)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        finding = data.get("finding")
        if not isinstance(finding, dict):
            return jsonify(error="finding is required"), 400
        finding["endpoint"] = str(finding.get("endpoint") or page.get("url") or "")
        return jsonify(finding=app.extensions["modules"].validate_finding(finding, authorization[0]))

    @app.post("/api/v1/modules/active-test")
    @protected
    def active_test_module():
        data = request.get_json(silent=True) or {}
        page = data.get("page") or {}
        try:
            authorization, error = authorized(page)
            target_origin = normalize_origin(data.get("target_url") or "")
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        if authorization[0] != target_origin:
            return jsonify(error="Active test target must match the authorized page origin"), 403
        if authorization[1].scope != "active_web_assessment":
            return jsonify(error="Active tests require active_web_assessment authorization"), 403
        if data.get("confirmed") is not True:
            return jsonify(error="Per-test confirmation is required"), 400
        test_type = str(data.get("test_type") or "")
        parameter = str(data.get("parameter") or "").strip()
        if not parameter or len(parameter) > 100 or not all(c.isalnum() or c in "_.-" for c in parameter):
            return jsonify(error="parameter must be 1-100 letters, digits, dot, underscore, or hyphen"), 400
        target_url = str(data.get("target_url"))[:4000]
        try:
            result = app.extensions["modules"].active_test(target_url, test_type, parameter)
        except (ValueError, OSError) as exc:
            return jsonify(error=str(exc)), 400
        except Exception as exc:
            return jsonify(error=f"Active test failed: {exc}"), 502
        auth_call("log_test", AuditLogEntry(
            timestamp=datetime.now().isoformat(), test_id=result["test_id"],
            target_url=authorization[0], endpoint_tested=target_url,
            test_type=test_type, payload_used=result.get("payload_used", ""),
            result="vulnerable" if result.get("vulnerable") else "not_vulnerable",
            confidence=float(result.get("confidence", 0)), performed_by=authorization[1].authorized_by,
            authorization_id=None, notes="Browser companion deterministic active test"))
        return jsonify(result=result)

    @app.post("/api/v1/modules/send-payload")
    @protected
    def send_payload_module():
        data = request.get_json(silent=True) or {}
        page = data.get("page") or {}
        try:
            authorization, error = authorized(page)
            target_url = str(data.get("target_url") or page.get("url") or "")[:4000]
            target_origin = normalize_origin(target_url)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        if authorization[0] != target_origin:
            return jsonify(error="Payload target must match the authorized page origin"), 403
        if authorization[1].scope != "active_web_assessment":
            return jsonify(error="Sending payloads requires active_web_assessment authorization"), 403
        if data.get("confirmed") is not True:
            return jsonify(error="Per-request confirmation is required"), 400
        method = str(data.get("method") or "")
        parameter = str(data.get("parameter") or "").strip()
        payload = str(data.get("payload") or "")
        if method not in {"GET", "POST_FORM", "POST_JSON"}:
            return jsonify(error="Unsupported payload request method"), 400
        if not parameter or len(parameter) > 100 or not all(c.isalnum() or c in "_.-" for c in parameter):
            return jsonify(error="parameter must be 1-100 letters, digits, dot, underscore, or hyphen"), 400
        if not payload or len(payload) > 4000:
            return jsonify(error="payload must contain 1-4000 characters"), 400
        try:
            result = app.extensions["modules"].send_payload(target_url, method, parameter, payload)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except Exception as exc:
            return jsonify(error=f"Payload request failed: {exc}"), 502
        auth_call("log_test", AuditLogEntry(
            timestamp=datetime.now().isoformat(), test_id=f"payload_{uuid4().hex[:12]}",
            target_url=authorization[0], endpoint_tested=target_url,
            test_type=f"payload_{method.lower()}", payload_used=payload,
            result=f"http_{result['status_code']}", confidence=0.0,
            performed_by=authorization[1].authorized_by, authorization_id=None,
            notes="Browser companion manually confirmed payload request"))
        return jsonify(result=result)

    @app.post("/api/v1/modules/port-scans")
    @protected
    def start_port_scan_module():
        data = request.get_json(silent=True) or {}
        page = data.get("page") or {}
        try:
            authorization, error = authorized(page)
            start_port = int(data.get("start_port", 1))
            end_port = int(data.get("end_port", 65535))
            timeout_ms = int(data.get("timeout_ms", 200))
        except (TypeError, ValueError) as exc:
            return jsonify(error=str(exc) or "Invalid port scan settings"), 400
        if error:
            return error
        if authorization[1].scope != "active_web_assessment":
            return jsonify(error="Port scanning requires active_web_assessment authorization"), 403
        if data.get("confirmed") is not True:
            return jsonify(error="Per-scan confirmation is required"), 400
        host = urlsplit(page.get("url", "")).hostname
        if not host:
            return jsonify(error="Authorized page has no scan hostname"), 400
        try:
            job = app.extensions["modules"].start_port_scan(
                host, start_port, end_port, timeout_ms)
        except ValueError as exc:
            return jsonify(error=str(exc)), 409
        auth_call("log_test", AuditLogEntry(
            timestamp=datetime.now().isoformat(), test_id=job["id"],
            target_url=authorization[0], endpoint_tested=host,
            test_type="tcp_port_scan", payload_used=f"{start_port}-{end_port}",
            result="started", confidence=0.0,
            performed_by=authorization[1].authorized_by, authorization_id=None,
            notes=f"Browser companion confirmed TCP scan; timeout={timeout_ms}ms"))
        return jsonify(job=job), 202

    @app.get("/api/v1/modules/port-scans/<job_id>")
    @protected
    def get_port_scan_module(job_id):
        job = app.extensions["modules"].get_port_scan(job_id)
        if not job:
            return jsonify(error="Port scan not found"), 404
        return jsonify(job=job)

    @app.post("/api/v1/chat")
    @protected
    def chat():
        data, page = request.get_json(silent=True) or {}, (request.get_json(silent=True) or {}).get("page") or {}
        message = str(data.get("message") or "").strip()
        if not message:
            return jsonify(error="message is required"), 400
        try:
            authorization, error = authorized(page)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if error:
            return error
        if app.extensions["conversations"] is None:
            from llm_conversation_core import ConversationManager
            app.extensions["conversations"] = ConversationManager()
        manager, conv_id = app.extensions["conversations"], data.get("conversation_id")
        if not conv_id:
            conv = manager.create_conversation(title=f"Browser assessment: {authorization[0]}",
                system_prompt="Assist with this explicitly authorized assessment. Use only supplied passive evidence, distinguish observations from confirmed vulnerabilities, and prioritize safe verification and remediation.")
            conv_id = conv.id
        context = {"url": str(page.get("url") or "")[:4000], "title": str(page.get("title") or "")[:500],
                   "forms": (page.get("forms") or [])[:25], "findings": (data.get("findings") or [])[:50]}
        answer = manager.send_message(f"Passive browser context:\n{json.dumps(context)}\n\nUser: {message[:8000]}", conv_id)
        return jsonify(conversation_id=conv_id, content=answer)

    return app


def main():
    parser = argparse.ArgumentParser(description="Run the Hades browser companion")
    parser.add_argument("--port", default=PORT, type=int)
    args = parser.parse_args()
    app = create_app()
    print(f"Hades companion: http://{HOST}:{args.port}")
    print(f"Pairing token: {app.config['COMPANION_TOKEN']}")
    app.run(host=HOST, port=args.port, debug=False)


if __name__ == "__main__":
    main()

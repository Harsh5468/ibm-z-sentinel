"""Standard-library, loopback-first IBM Z Sentinel dashboard."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
from urllib.parse import parse_qs, quote, urlsplit

from sentinel.correlation import Incident, correlate_incidents, dependency_edges
from sentinel.detection import enrich_with_findings
from sentinel.evidence import generate_demo_events
from sentinel.investigation import investigate
from sentinel.storage import SentinelStore


WARNING = ("SYNTHETIC DEMO MODE — Generated records only. No live z/OS, RACF or SMF "
           "connection. No system actions are executed.")
MAX_POST_BYTES = 4096
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
INCIDENT_PATTERN = re.compile(r"^INC-[0-9A-F]{10}$")


class RequestError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def refresh_demo(store: SentinelStore, seed: int, window_minutes: int) -> None:
    """Regenerate and idempotently upsert a synthetic snapshot via the existing store."""
    if not 0 <= seed <= 999999:
        raise ValueError("seed must be between 0 and 999999")
    if not 1 <= window_minutes <= 240:
        raise ValueError("window must be between 1 and 240 minutes")
    evidence = enrich_with_findings(generate_demo_events(seed))
    incidents = correlate_incidents(evidence, window_minutes=window_minutes)
    store.save_demo_snapshot(seed, window_minutes, evidence, incidents)


def _severity(incident: Incident) -> str:
    levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max((item.severity for item in incident.evidence),
               key=lambda value: levels.get(value, 0), default="info")


def _layout(title: str, body: str) -> bytes:
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><title>{_e(title)} · IBM Z Sentinel</title>
<style>
:root{{--navy:#071426;--panel:#10243d;--panel2:#142e4d;--line:#23496c;--blue:#4ea1ff;--cyan:#67d5e8;--text:#edf5ff;--muted:#a9bfd6;--gold:#ffd166;--red:#ff7185;--green:#79ddb0}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at 15% 0%,#122f50 0,transparent 42%),var(--navy);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
a{{color:#8dc5ff;text-decoration:none}}a:hover{{text-decoration:underline}}.shell{{width:min(1440px,calc(100% - 36px));margin:auto;padding:28px 0 56px}}
.brand{{display:flex;align-items:center;gap:14px;margin-bottom:20px}}.mark{{width:46px;height:46px;border:1px solid #3d7caf;border-radius:13px;display:grid;place-items:center;color:var(--cyan);font-size:24px;background:#0b2038}}
h1{{font-size:clamp(1.7rem,4vw,2.5rem);margin:0;letter-spacing:-.04em}}h2{{font-size:1.25rem;margin:0 0 15px}}h3{{font-size:1.03rem;margin:0 0 9px}}p{{margin:.35rem 0;color:var(--muted)}}.eyebrow{{color:var(--cyan);text-transform:uppercase;letter-spacing:.13em;font-size:.72rem;font-weight:750}}
.warning{{border:1px solid #9d7622;background:#302811;color:#ffe59b;padding:13px 16px;border-radius:11px;margin:18px 0 22px;font-weight:750}}
.grid{{display:grid;gap:16px}}.metrics{{grid-template-columns:repeat(4,minmax(0,1fr));margin:20px 0}}.metric,.panel,.card{{background:linear-gradient(145deg,rgba(20,46,77,.96),rgba(13,32,55,.96));border:1px solid var(--line);border-radius:15px;padding:18px;box-shadow:0 10px 32px #0002}}
.metric label,.muted{{display:block;color:var(--muted);font-size:.82rem}}.metric strong{{font-size:1.65rem;display:block;margin-top:4px}}.columns{{grid-template-columns:minmax(270px,.85fr) minmax(0,1.8fr);align-items:start}}
.incident-list{{display:grid;gap:11px}}.incident{{padding:15px;border:1px solid var(--line);background:#0b1d33;border-radius:12px;display:block;color:var(--text)}}.incident.selected{{border-color:var(--blue);box-shadow:inset 3px 0 var(--blue)}}.incident strong{{display:block;font-size:1rem}}.pill{{display:inline-block;border:1px solid #35648d;border-radius:99px;padding:2px 9px;font-size:.72rem;color:#b8dcff;margin:7px 5px 0 0;text-transform:uppercase}}.pill.critical,.pill.high{{border-color:#a94b61;color:#ffb0bc}}.score{{font-weight:800;color:#fff;font-size:1.3rem}}
.detail-head{{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}}.riskbar{{height:8px;background:#071426;border-radius:10px;overflow:hidden;margin:12px 0}}.riskbar span{{display:block;height:100%;background:linear-gradient(90deg,#42c9e6,#ffbf69,#ff7185)}}
.section{{margin-top:21px}}.list{{display:grid;gap:9px}}.item{{padding:12px 14px;border:1px solid #203e5d;border-radius:10px;background:#0b1c30}}.item p{{color:var(--text)}}.refs,code,pre{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.82rem;color:#9dd9ff;overflow-wrap:anywhere}}.timeline{{border-left:2px solid #27517a;margin-left:7px;padding-left:18px;display:grid;gap:12px}}.timeline .item{{position:relative}}.timeline .item:before{{content:"";position:absolute;left:-25px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 4px var(--panel)}}
form{{margin-top:10px}}input[type=text],input[type=number]{{color:var(--text);background:#071426;border:1px solid #355875;border-radius:8px;padding:10px 11px;max-width:100%}}button{{background:#176bb5;color:white;border:0;padding:10px 14px;border-radius:8px;font-weight:750;cursor:pointer}}button.secondary{{background:#344b63}}button.reject{{background:#823a4a}}button:hover{{filter:brightness(1.15)}}.controls{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}.confirm{{display:flex;gap:8px;align-items:center;color:var(--muted);margin:9px 0}}.error{{border:1px solid #a94b61;background:#3a1722;padding:20px;border-radius:12px}}.footer{{color:var(--muted);font-size:.8rem;margin-top:28px;border-top:1px solid var(--line);padding-top:16px}}
@media(max-width:850px){{.columns{{grid-template-columns:1fr}}}}@media(max-width:600px){{.shell{{width:min(100% - 22px,1440px);padding-top:16px}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}}.metric{{padding:13px}}.metric strong{{font-size:1.35rem}}.detail-head{{display:block}}}}
</style></head><body><main class="shell"><div class="brand"><div class="mark" aria-hidden="true">Z</div><div><div class="eyebrow">Unified Mainframe Intelligence &amp; Protection</div><h1>IBM Z Sentinel</h1></div></div>
<div class="warning">{_e(WARNING)}</div>{body}<div class="footer">IBM Z Sentinel · Synthetic evidence only · SQLite local history · Human decisions are recorded, never executed.</div></main></body></html>"""
    return document.encode("utf-8")


def _csrf_cookie(handler: BaseHTTPRequestHandler) -> str:
    cookie = SimpleCookie()
    try:
        cookie.load(handler.headers.get("Cookie", ""))
        token = cookie.get(_csrf_cookie_name(handler))
        if token and TOKEN_PATTERN.fullmatch(token.value):
            return token.value
    except (ValueError, TypeError):
        pass
    return secrets.token_urlsafe(32)


def _csrf_cookie_name(handler: BaseHTTPRequestHandler) -> str:
    """Use a per-port cookie name because browser cookies are not port-scoped."""
    return f"sentinel_csrf_{handler.server.server_port}"


def _normalized_authority(value: str, *, origin: bool) -> tuple[str, str, int] | None:
    """Parse and normalize an HTTP origin/Host authority without accepting userinfo."""
    try:
        # HTTP field values can contain optional whitespace at their boundaries.
        value = value.strip(" \t")
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
            return None
        parsed = urlsplit(value if origin else "//" + value)
        scheme = parsed.scheme.lower() if origin else "http"
        if scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
            return None
        # Origin identity is exactly scheme + authority. A path is not part of
        # an origin and must not make an otherwise same-origin request fail.
        if not origin and (parsed.query or parsed.fragment or parsed.path):
            return None
        if origin and (parsed.query or parsed.fragment):
            return None
        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname:
            return None
        try:
            address = ipaddress.ip_address(hostname)
            host_key = "<loopback>" if address.is_loopback else address.compressed.lower()
        except ValueError:
            host_key = "<loopback>" if hostname == "localhost" else hostname
        port = parsed.port or 80
        if not 1 <= port <= 65535:
            return None
        return scheme, host_key, port
    except ValueError:
        return None


def _normalized_referer_authority(value: str) -> tuple[str, str, int] | None:
    """Extract an HTTP Referer origin while allowing its ordinary path and query."""
    try:
        value = value.strip(" \t")
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
            return None
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc or parsed.fragment:
            return None
        return _normalized_authority(f"{parsed.scheme}://{parsed.netloc}", origin=True)
    except ValueError:
        return None


def _canonical_hostname(value: str, *, origin: bool) -> str | None:
    """Canonicalize a literal hostname without collapsing distinct loopback names."""
    try:
        parsed = urlsplit(value if origin else "//" + value.strip(" \t"))
        if not parsed.hostname:
            return None
        hostname = parsed.hostname.rstrip(".").lower()
        try:
            return ipaddress.ip_address(hostname).compressed.lower()
        except ValueError:
            return hostname
    except ValueError:
        return None


def _same_authority(first_value: str, second_value: str, *, first_is_origin: bool,
                    first_is_referer: bool = False) -> bool:
    first = (_normalized_referer_authority(first_value) if first_is_referer
             else _normalized_authority(first_value, origin=first_is_origin))
    second = _normalized_authority(second_value, origin=False)
    return (
        first is not None and second is not None and first == second
        and _canonical_hostname(first_value, origin=first_is_origin)
        == _canonical_hostname(second_value, origin=False)
    )


def _matches_local_dashboard_authority(host: str, bind_host: str, server_port: int) -> bool:
    """Require the opaque-Origin fallback Host to name this loopback listener."""
    authority = _normalized_authority(host, origin=False)
    if authority is None or authority[2] != server_port or authority[1] != "<loopback>":
        return False
    try:
        host_name = urlsplit("//" + host.strip(" \t")).hostname
        if not host_name:
            return False
        host_name = host_name.rstrip(".").lower()
        bind_name = bind_host.split("%", 1)[0].rstrip(".").lower()
        if host_name == "localhost":
            return bind_name == "localhost" or ipaddress.ip_address(bind_name).is_loopback
        return ipaddress.ip_address(host_name) == ipaddress.ip_address(bind_name)
    except ValueError:
        return False


def _authority_classification(value: str, *, origin: bool) -> str:
    """Return safe scheme/host/port categories; never include raw header values."""
    try:
        candidate = value.strip(" \t")
        if origin and not candidate:
            return "kind=missing,scheme=missing,host=missing,port=default"
        if origin and candidate.lower() == "null":
            return "kind=opaque,scheme=missing,host=missing,port=default"
        parsed = urlsplit(candidate if origin else "//" + candidate)
        scheme = parsed.scheme.lower() if origin else "http"
        scheme_class = scheme if scheme in {"http", "https"} else ("other" if scheme else "missing")
        hostname = parsed.hostname
        if not hostname:
            host_class = "missing"
        else:
            hostname = hostname.rstrip(".").lower()
            try:
                address = ipaddress.ip_address(hostname)
                host_class = "loopback" if address.is_loopback else (
                    "ipv6" if address.version == 6 else "ipv4")
            except ValueError:
                host_class = "loopback" if hostname == "localhost" else "dns"
        try:
            port_value = parsed.port
            default_port = 443 if scheme_class == "https" else 80
            port_class = "default" if port_value is None or port_value == default_port else "nondefault"
        except ValueError:
            port_class = "invalid"
        kind = "absolute" if origin and parsed.scheme and parsed.netloc else "authority"
        return f"kind={kind},scheme={scheme_class},host={host_class},port={port_class}"
    except ValueError:
        return "scheme=malformed,host=malformed,port=invalid"


def _hidden_csrf(token: str) -> str:
    return f'<input type="hidden" name="csrf" value="{_e(token)}">'


def render_dashboard(store: SentinelStore, token: str, selected_id: str | None = None,
                     notice: str = "", use_granite: bool = False) -> bytes:
    if not store.has_incidents():
        refresh_demo(store, 42, 90)
    incidents = store.list_incidents()
    counts = store.counts()
    if selected_id is not None and not any(item.incident_id == selected_id for item in incidents):
        raise RequestError(HTTPStatus.NOT_FOUND, "Incident not found")
    selected = next((item for item in incidents if item.incident_id == selected_id),
                    incidents[0] if incidents else None)
    high_risk = sum(item.risk.score >= 55 for item in incidents)
    body = []
    if notice:
        body.append(f'<div class="item" role="status">{_e(notice)}</div>')
    body.append('<section class="grid metrics">')
    for label, value in (("Stored evidence", counts["evidence_events"]), ("Incident history", counts["incidents"]),
                         ("High / critical", high_risk), ("Approval decisions", counts["approval_history"])):
        body.append(f'<div class="metric"><label>{_e(label)}</label><strong>{_e(value)}</strong></div>')
    body.append('</section>')
    body.append(f'''<section class="panel"><h2>Synthetic demo controls</h2>
<form method="post" action="/refresh">{_hidden_csrf(token)}<div class="controls">
<label for="seed">Seed</label><input id="seed" name="seed" type="number" min="0" max="999999" value="42" required>
<label for="window">Correlation window (minutes)</label><input id="window" name="window" type="number" min="1" max="240" value="90" required>
<button type="submit">Load / refresh seeded demo</button></div></form>
<p>Refreshing a seed upserts stable evidence and incidents. Existing approval decisions are retained.</p></section>''')
    if not selected:
        body.append('<section class="panel"><p>No incidents are available.</p></section>')
        return _layout("Dashboard", "".join(body))

    body.append('<section class="grid columns section"><aside class="panel"><h2>Incident queue</h2><div class="incident-list">')
    for incident in incidents:
        classes = "incident selected" if incident.incident_id == selected.incident_id else "incident"
        url = "/?incident=" + quote(incident.incident_id, safe="")
        body.append(f'<a class="{classes}" href="{_e(url)}"><strong>{_e(incident.incident_id)}</strong>'
                    f'<span class="muted">{_e(incident.business_process or "Cross-signal incident")}</span>'
                    f'<span class="pill {_e(incident.risk.band)}">{_e(incident.risk.band)} risk</span>'
                    f'<span class="pill">{_e(incident.business_criticality)} business</span>'
                    f'<span class="score">{incident.risk.score}/100</span>'
                    f'<span class="muted">{len(incident.evidence)} correlated events</span></a>')
    body.append('</div></aside><article class="panel">')
    severity = _severity(selected)
    body.append(f'''<div class="detail-head"><div><div class="eyebrow">{_e(selected.business_process or "Cross-signal incident")}</div>
<h2>{_e(selected.incident_id)}</h2><p>Severity <b>{_e(severity.upper())}</b> · Business criticality <b>{_e(selected.business_criticality.upper())}</b></p>
<p>Actors: {_e(", ".join(selected.actors) or "Not attributed")}</p></div><div class="score">{selected.risk.score}<span class="muted"> / 100 · {_e(selected.risk.band)}</span></div></div>
<div class="riskbar" aria-label="Risk score"><span style="width:{max(0,min(100,selected.risk.score))}%"></span></div>
<h3>Explainable risk factors</h3><ul>{"".join(f"<li>{_e(reason)}</li>" for reason in selected.risk.reasons)}</ul>''')

    sources = Counter(item.source_type for item in selected.evidence)
    body.append('<section class="section"><h3>Evidence sources and IDs</h3><p>' +
                " · ".join(f"{_e(source)} ({amount})" for source, amount in sources.most_common()) +
                '</p><div class="list">')
    for event in selected.evidence:
        body.append(f'<div class="item"><b>{_e(event.evidence_id)}</b> · {_e(event.event_type)}'
                    f'<span class="muted">{_e(event.source_type)} · {_e(event.actor)} → {_e(event.target)}</span></div>')
    body.append('</div></section>')

    event_by_id = {item.evidence_id: item for item in selected.evidence}
    body.append('<section class="section"><h3>Dependency relationships</h3><div class="list">')
    edges = dependency_edges(selected)
    if edges:
        for edge in edges:
            source, target = event_by_id[edge.source_evidence_id], event_by_id[edge.target_evidence_id]
            body.append(f'<div class="item">{_e(source.event_type)} <span class="refs">{_e(edge.source_evidence_id)}</span>'
                        f' → {_e(target.event_type)} <span class="refs">{_e(edge.target_evidence_id)}</span>'
                        f'<span class="muted">{_e(edge.relationship)}</span></div>')
    else:
        body.append('<p>No explicit evidence-ID dependencies recorded.</p>')
    body.append('</div></section>')

    investigation_url = "/?incident=" + quote(selected.incident_id, safe="")
    if use_granite:
        body.append(f'<p><a href="{_e(investigation_url)}">Use deterministic investigation</a></p>')
    else:
        body.append(f'<p><a href="{_e(investigation_url + "&granite=1")}">Try optional local Granite</a></p>')
    report = investigate(selected, use_granite=use_granite)
    provider = "local Granite with deterministic fallback" if use_granite else "deterministic"
    body.append(f'<section class="section"><h3>Evidence-grounded investigation · {_e(provider)}</h3>'
                f'<p>{_e(report["note"])}</p><div class="list">')
    for claim in report["claims"]:
        body.append(f'<div class="item"><p>{_e(claim["conclusion"])}</p><span class="muted">Supporting evidence IDs</span>'
                    f'<span class="refs">{_e(", ".join(claim["evidence_ids"]))}</span></div>')
    body.append('</div></section>')

    body.append('<section class="section"><h3>Chronological event timeline</h3><div class="timeline">')
    for event in sorted(selected.evidence, key=lambda item: item.occurred_at):
        timestamp = datetime.fromisoformat(event.occurred_at).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        details = json.dumps(event.attributes, indent=2, sort_keys=True, ensure_ascii=False)
        body.append(f'<div class="item"><b>{_e(timestamp)} · {_e(event.event_type)} · {_e(event.severity.upper())}</b>'
                    f'<span class="muted">{_e(event.evidence_id)} · Source: {_e(event.source_type)} · Actor: {_e(event.actor)} · Target: {_e(event.target)}</span>'
                    f'<p>{_e(event.summary)}</p><details><summary>Evidence attributes · synthetic: {_e(event.synthetic)}</summary>'
                    f'<pre>{_e(details)}</pre></details></div>')
    body.append('</div></section>')

    body.append('<section class="section"><h3>Remediation recommendations</h3><p>Approvals record a human decision only. No remediation or system change is executed.</p><div class="list">')
    for recommendation in store.list_recommendations(selected.incident_id):
        action_id = _e(recommendation.action_id)
        body.append(f'<div class="item"><h3>{_e(recommendation.title)}</h3><p>{_e(recommendation.rationale)}</p>'
                    f'<p>Approval: <b>{_e(recommendation.approval_status)}</b> · Execution: <b>{_e(recommendation.execution_status)}</b></p>'
                    f'<p class="refs">Evidence: {_e(", ".join(recommendation.evidence_ids))}</p>'
                    f'<form method="post" action="/decision">{_hidden_csrf(token)}'
                    f'<input type="hidden" name="incident_id" value="{_e(selected.incident_id)}">'
                    f'<input type="hidden" name="action_id" value="{action_id}">'
                    '<div class="controls"><label for="approver-' + action_id + '">Approver name or operator ID</label>'
                    '<input type="text" maxlength="128" required name="approver" id="approver-' + action_id + '"></div>'
                    '<label class="confirm"><input type="checkbox" name="confirmed" value="yes" required> I explicitly confirm this recorded decision; no action will be executed.</label>'
                    '<div class="controls"><button name="decision" value="Approved" type="submit">Confirm approval</button>'
                    '<button class="reject" name="decision" value="Rejected" type="submit">Confirm rejection</button></div></form></div>')
    body.append('</div></section>')

    audit = store.list_approval_history(selected.incident_id)
    body.append('<section class="section"><h3>Persistent approval audit</h3><div class="list">')
    if audit:
        for row in audit:
            body.append(f'<div class="item">{_e(row["decided_at"])} · {_e(row["decision"])} · {_e(row["action_id"])} · approver {_e(row["approver"])}</div>')
    else:
        body.append('<p>No approval decisions recorded for this incident.</p>')
    body.append('</div></section></article></section>')
    return _layout("Incident dashboard", "".join(body))


def make_handler(store: SentinelStore):
    class SentinelHandler(BaseHTTPRequestHandler):
        server_version = "IBMZSentinel/1.0"
        sys_version = ""

        def log_message(self, _format: str, *args: object) -> None:
            # Avoid logging request values, approver names, query strings, or form data.
            return

        def _send(self, status: HTTPStatus, body: bytes, csrf: str | None = None,
                  location: str | None = None) -> None:
            self.send_response(status.value)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if csrf:
                self.send_header("Set-Cookie", f"{_csrf_cookie_name(self)}={csrf}; Path=/; HttpOnly; SameSite=Strict")
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(body)

        def _error(self, error: RequestError, csrf: str | None = None) -> None:
            content = _layout("Request error", f'<section class="error"><h2>{_e(error.status.phrase)}</h2><p>{_e(error.message)}</p><a href="/">Return to dashboard</a></section>')
            self._send(error.status, content, csrf=csrf)

        def _read_form(self) -> dict[str, str]:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/x-www-form-urlencoded":
                raise RequestError(HTTPStatus.BAD_REQUEST, "Expected a form submission")
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError as exc:
                raise RequestError(HTTPStatus.BAD_REQUEST, "Malformed request length") from exc
            if length < 0 or length > MAX_POST_BYTES:
                raise RequestError(HTTPStatus.BAD_REQUEST, "Request body is missing or too large")
            raw = self.rfile.read(length)
            try:
                parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                                  max_num_fields=20)
            except (UnicodeDecodeError, ValueError) as exc:
                raise RequestError(HTTPStatus.BAD_REQUEST, "Malformed form data") from exc
            if any(len(values) != 1 for values in parsed.values()):
                raise RequestError(HTTPStatus.BAD_REQUEST, "Duplicate form fields are not allowed")
            return {key: values[0] for key, values in parsed.items()}

        def _check_csrf(self, form: dict[str, str]) -> str:
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                token_cookie = cookie.get(_csrf_cookie_name(self))
                cookie_token = token_cookie.value if token_cookie else ""
            except (ValueError, AttributeError):
                cookie_token = ""
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            referer = self.headers.get("Referer", "")
            origin_authority = _normalized_authority(origin, origin=True)
            host_authority = _normalized_authority(host, origin=False)
            referer_authority = _normalized_referer_authority(referer)
            bind_host = str(self.server.server_address[0]).lower()
            try:
                loopback_bound = ipaddress.ip_address(bind_host.split("%", 1)[0]).is_loopback
            except ValueError:
                loopback_bound = bind_host == "localhost"
            opaque_origin = origin.strip(" \t") == "null"
            cookie_token_format = TOKEN_PATTERN.fullmatch(cookie_token) is not None
            cookie_form_token_match = secrets.compare_digest(cookie_token, form.get("csrf", ""))
            fetch_site = self.headers.get("Sec-Fetch-Site")
            fetch_mode = self.headers.get("Sec-Fetch-Mode")
            # Referer is the required independent same-origin signal. Browsers
            # that send Fetch Metadata must send a complete, consistent pair;
            # older/compatibility clients may omit both headers.
            fetch_metadata_consistent = (
                (fetch_site is None and fetch_mode is None)
                or (fetch_site == "same-origin" and fetch_mode == "navigate")
            )
            referer_matches_host = (
                referer_authority is not None and host_authority is not None
                and _same_authority(referer, host, first_is_origin=True,
                                    first_is_referer=True)
            )
            opaque_origin_fallback = (
                opaque_origin
                and cookie_token_format
                and cookie_form_token_match
                and fetch_metadata_consistent
                and referer_matches_host
                and loopback_bound
                and _matches_local_dashboard_authority(
                    host, bind_host, self.server.server_port)
            )
            same_origin = (
                origin_authority is not None and host_authority is not None
                and _same_authority(origin, host, first_is_origin=True)
            )
            checks = {
                "cookie_token_format": cookie_token_format,
                "cookie_form_token_match": cookie_form_token_match,
                "origin_parse_success": origin_authority is not None or opaque_origin_fallback,
                "host_parse_success": host_authority is not None,
                "authority_match": same_origin or opaque_origin_fallback,
                "loopback_origin_condition": (
                    not loopback_bound
                    or (origin_authority is not None and origin_authority[1] == "<loopback>")
                    or opaque_origin_fallback
                ),
            }
            failed_checks = [name for name, passed in checks.items() if not passed]
            if failed_checks:
                origin_class = _authority_classification(origin, origin=True)
                host_class = _authority_classification(host, origin=False)
                referer_class = _authority_classification(referer, origin=True)
                fetch_site_class = ("same-origin" if self.headers.get("Sec-Fetch-Site") == "same-origin"
                                    else "missing" if not self.headers.get("Sec-Fetch-Site") else "other")
                fetch_mode_class = ("navigate" if self.headers.get("Sec-Fetch-Mode") == "navigate"
                                    else "missing" if not self.headers.get("Sec-Fetch-Mode") else "other")
                print("CSRF validation failed: " + ", ".join(failed_checks)
                      + f"; origin[{origin_class}]; host[{host_class}]"
                      + f"; referer[{referer_class}]; fetch_site={fetch_site_class};"
                      + f" fetch_mode={fetch_mode_class}; loopback_bound={loopback_bound};"
                      + f" local_host_match={_matches_local_dashboard_authority(host, bind_host, self.server.server_port)}",
                      file=sys.stderr)
                raise RequestError(HTTPStatus.FORBIDDEN, "Request security check failed. Reload the dashboard and try again.")
            return cookie_token

        def do_GET(self) -> None:
            token = _csrf_cookie(self)
            try:
                parts = urlsplit(self.path)
                if parts.path != "/":
                    raise RequestError(HTTPStatus.NOT_FOUND, "Page not found")
                query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=False, max_num_fields=10)
                if set(query) - {"incident", "status", "granite"} or any(len(values) != 1 for values in query.values()):
                    raise RequestError(HTTPStatus.BAD_REQUEST, "Malformed dashboard selection")
                selected_id = query.get("incident", [None])[0]
                if selected_id is not None and not INCIDENT_PATTERN.fullmatch(selected_id):
                    raise RequestError(HTTPStatus.NOT_FOUND, "Incident not found")
                granite_value = query.get("granite", ["0"])[0]
                if granite_value not in {"0", "1"}:
                    raise RequestError(HTTPStatus.BAD_REQUEST, "Investigation mode is invalid")
                status_code = query.get("status", [""])[0]
                notice = {"refreshed": "Synthetic demo refreshed. Existing decisions were retained.",
                          "recorded": "Human decision recorded. No action was executed."}.get(status_code, "")
                self._send(HTTPStatus.OK, render_dashboard(store, token, selected_id, notice,
                                                           use_granite=granite_value == "1"), csrf=token)
            except RequestError as error:
                self._error(error, csrf=token)
            except (ValueError, OSError, sqlite3.Error):
                self._error(RequestError(HTTPStatus.BAD_REQUEST, "Unable to render this request."), csrf=token)

        def do_POST(self) -> None:
            try:
                parts = urlsplit(self.path)
                if parts.query or parts.path not in {"/refresh", "/decision"}:
                    raise RequestError(HTTPStatus.NOT_FOUND, "Page not found")
                form = self._read_form()
                self._check_csrf(form)
                if parts.path == "/refresh":
                    if set(form) != {"csrf", "seed", "window"}:
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Malformed refresh request")
                    if not re.fullmatch(r"\d{1,6}", form["seed"]) or not re.fullmatch(r"\d{1,3}", form["window"]):
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Seed or correlation window is invalid")
                    seed, window = int(form["seed"]), int(form["window"])
                    if seed > 999999 or not 1 <= window <= 240:
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Seed or correlation window is outside the allowed range")
                    refresh_demo(store, seed, window)
                    destination = "/?status=refreshed"
                else:
                    required = {"csrf", "incident_id", "action_id", "decision", "approver", "confirmed"}
                    if set(form) != required:
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Malformed approval request")
                    incident_id, action_id = form["incident_id"], form["action_id"]
                    if not INCIDENT_PATTERN.fullmatch(incident_id):
                        raise RequestError(HTTPStatus.NOT_FOUND, "Incident not found")
                    if form["decision"] not in {"Approved", "Rejected"}:
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Decision must be Approved or Rejected")
                    approver = form["approver"].strip()
                    if not approver or len(approver) > 128:
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Approver is required and must be at most 128 characters")
                    if form["confirmed"] != "yes":
                        raise RequestError(HTTPStatus.BAD_REQUEST, "Explicit confirmation is required")
                    incident = next((item for item in store.list_incidents() if item.incident_id == incident_id), None)
                    if incident is None:
                        raise RequestError(HTTPStatus.NOT_FOUND, "Incident not found")
                    if not any(item.action_id == action_id for item in store.list_recommendations(incident_id)):
                        raise RequestError(HTTPStatus.NOT_FOUND, "Recommendation not found")
                    store.record_decision(incident_id, action_id, form["decision"], approver, confirmed=True)
                    destination = "/?incident=" + quote(incident_id, safe="") + "&status=recorded"
                self.send_response(HTTPStatus.SEE_OTHER.value)
                self.send_header("Location", destination)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            except RequestError as error:
                self._error(error, csrf=_csrf_cookie(self))
            except (KeyError, ValueError, PermissionError):
                self._error(RequestError(HTTPStatus.BAD_REQUEST, "The submitted decision could not be recorded."),
                            csrf=_csrf_cookie(self))
            except (OSError, RuntimeError, sqlite3.Error):
                self._error(RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "The request could not be completed."),
                            csrf=_csrf_cookie(self))

    return SentinelHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="IBM Z Sentinel synthetic incident dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8501, help="port (default: 8501)")
    parser.add_argument("--database", default=os.getenv("SENTINEL_DB_PATH", "data/sentinel.db"),
                        help="SQLite database path (default: SENTINEL_DB_PATH or data/sentinel.db)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    store = SentinelStore(Path(args.database))
    server = HTTPServer((args.host, args.port), make_handler(store))
    print(f"IBM Z Sentinel listening at http://{args.host}:{args.port}/ (synthetic demo only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping IBM Z Sentinel.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

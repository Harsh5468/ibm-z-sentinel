from __future__ import annotations

from contextlib import redirect_stderr
from email.message import Message
from http import HTTPStatus
from http.server import HTTPServer
import io
from pathlib import Path
import re
import tempfile
from threading import Thread
from types import SimpleNamespace
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener
from http.cookiejar import CookieJar

from sentinel.storage import SentinelStore
from web_app import (RequestError, _authority_classification, _csrf_cookie_name,
                     _normalized_authority, make_handler)


class DashboardHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = SentinelStore(Path(self.temp_dir.name) / "sentinel.db")
        self.server = HTTPServer(("127.0.0.1", 0), make_handler(self.store))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.csrf_cookie_name = f"sentinel_csrf_{self.server.server_port}"
        self.cookies = CookieJar()
        self.client = build_opener(HTTPCookieProcessor(self.cookies))
        self.page = self._get("/")
        self.csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', self.page).group(1)
        self.incident = self.store.list_incidents()[0]
        self.recommendation = self.store.list_recommendations(self.incident.incident_id)[0]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def _get(self, path: str) -> str:
        with self.client.open(self.base + path, timeout=3) as response:
            self.assertEqual(response.status, HTTPStatus.OK)
            return response.read().decode("utf-8")

    def _post(self, path: str, fields: dict[str, str], *, csrf: bool = True,
              origin: bool = True, origin_value: str | None = None,
              host_value: str | None = None, referer_value: str | None = None,
              fetch_site_value: str | None = None, fetch_mode_value: str | None = None):
        body = urlencode(fields).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if csrf:
            headers["Cookie"] = f"{self.csrf_cookie_name}={self.csrf}"
        else:
            headers["Cookie"] = f"{self.csrf_cookie_name}=invalid"
        if origin:
            headers["Origin"] = origin_value or self.base
        if host_value:
            headers["Host"] = host_value
        if referer_value:
            headers["Referer"] = referer_value
        if fetch_site_value:
            headers["Sec-Fetch-Site"] = fetch_site_value
        if fetch_mode_value:
            headers["Sec-Fetch-Mode"] = fetch_mode_value
        request = Request(self.base + path, data=body, headers=headers, method="POST")
        try:
            return self.client.open(request, timeout=3)
        except HTTPError as error:
            return error

    def _post_with_diagnostics(self, path: str, fields: dict[str, str], **kwargs):
        diagnostics = io.StringIO()
        with redirect_stderr(diagnostics):
            response = self._post(path, fields, **kwargs)
        return response, diagnostics.getvalue()

    def test_dashboard_renders_incident_evidence_dependencies_and_timeline(self):
        incident = self.incident
        html = self.page
        self.assertIn("SYNTHETIC DEMO MODE — Generated records only", html)
        self.assertIn(incident.incident_id, html)
        self.assertIn(str(incident.risk.score), html)
        for event in incident.evidence:
            self.assertIn(event.evidence_id, html)
            self.assertIn(event.source_type, html)
        self.assertIn("Dependency relationships", html)
        self.assertIn("Evidence-grounded investigation", html)
        self.assertIn("Chronological event timeline", html)
        self.assertIn("Remediation recommendations", html)
        self.assertIn('method="post" action="/decision"', html)
        self.assertIn('method="post" action="/refresh"', html)

    def test_invalid_incident_selection_returns_safe_not_found_page(self):
        try:
            self.client.open(self.base + "/?incident=%3Cscript%3Ealert(1)%3C%2Fscript%3E", timeout=3)
            self.fail("Expected invalid incident to be rejected")
        except HTTPError as error:
            self.assertEqual(error.code, HTTPStatus.NOT_FOUND)
            body = error.read().decode("utf-8")
            self.assertIn("Incident not found", body)
            self.assertNotIn("<script>", body)

    def test_missing_invalid_csrf_token_and_cross_origin_are_rejected(self):
        form = {"csrf": self.csrf, "seed": "42", "window": "90"}
        missing_cookie = self._post("/refresh", form, csrf=False)
        self.assertEqual(missing_cookie.code, HTTPStatus.FORBIDDEN)
        missing_form_token = self._post("/refresh", {"seed": "42", "window": "90"})
        self.assertEqual(missing_form_token.code, HTTPStatus.FORBIDDEN)
        invalid_form_token = self._post("/refresh", {**form, "csrf": "invalid-token"})
        self.assertEqual(invalid_form_token.code, HTTPStatus.FORBIDDEN)
        cross_origin = self._post("/refresh", form, origin_value="http://attacker.invalid")
        self.assertEqual(cross_origin.code, HTTPStatus.FORBIDDEN)

    def test_localhost_and_loopback_host_forms_are_normalized_as_same_origin(self):
        response = self._post("/refresh", {"csrf": self.csrf, "seed": "42", "window": "90"},
                              origin_value=f"http://LOCALHOST:{self.server.server_port}",
                              host_value=f"localhost:{self.server.server_port}")
        self.assertEqual(response.status, HTTPStatus.OK)

    def test_exact_linuxone_loopback_origin_host_and_matching_tokens_pass_handler_check(self):
        handler_type = make_handler(self.store)
        handler = object.__new__(handler_type)
        handler.server = SimpleNamespace(server_port=8501, server_address=("127.0.0.1", 8501))
        handler.headers = Message()
        handler.headers["Origin"] = "http://127.0.0.1:8501"
        handler.headers["Host"] = "127.0.0.1:8501"
        handler.headers["Cookie"] = f"{_csrf_cookie_name(handler)}={self.csrf}"

        self.assertEqual(_normalized_authority("http://127.0.0.1:8501", origin=True),
                         ("http", "<loopback>", 8501))
        self.assertEqual(handler._check_csrf({"csrf": self.csrf}), self.csrf)

    def test_missing_origin_is_explicitly_rejected(self):
        handler_type = make_handler(self.store)
        handler = object.__new__(handler_type)
        handler.server = SimpleNamespace(server_port=8501, server_address=("127.0.0.1", 8501))
        handler.headers = Message()
        handler.headers["Host"] = "127.0.0.1:8501"
        handler.headers["Referer"] = "http://127.0.0.1:8501/"
        handler.headers["Sec-Fetch-Site"] = "same-origin"
        handler.headers["Sec-Fetch-Mode"] = "navigate"
        handler.headers["Cookie"] = f"{_csrf_cookie_name(handler)}={self.csrf}"

        with self.assertRaises(RequestError) as raised:
            handler._check_csrf({"csrf": self.csrf})
        self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
        self.assertIn("kind=missing", _authority_classification("", origin=True))
        self.assertIn("kind=opaque", _authority_classification("null", origin=True))

    def _csrf_test_handler(self, *, origin="null", host="__same_origin__",
                           referer="__same_origin__",
                           fetch_site="same-origin", fetch_mode="navigate",
                           bind_host="127.0.0.1", token=None):
        handler_type = make_handler(self.store)
        handler = object.__new__(handler_type)
        port = self.server.server_port
        if host == "__same_origin__":
            host = f"127.0.0.1:{port}"
        if referer == "__same_origin__":
            referer = f"{self.base}/?incident=demo"
        handler.server = SimpleNamespace(server_port=port, server_address=(bind_host, port))
        handler.headers = Message()
        if origin is not None:
            handler.headers["Origin"] = origin
        if host is not None:
            handler.headers["Host"] = host
        if referer is not None:
            handler.headers["Referer"] = referer
        if fetch_site is not None:
            handler.headers["Sec-Fetch-Site"] = fetch_site
        if fetch_mode is not None:
            handler.headers["Sec-Fetch-Mode"] = fetch_mode
        handler.headers["Cookie"] = f"{_csrf_cookie_name(handler)}={self.csrf}"
        return handler, {"csrf": self.csrf if token is None else token}

    def test_opaque_origin_requires_local_host_referer_and_matching_csrf(self):
        handler, form = self._csrf_test_handler()
        self.assertEqual(handler._check_csrf(form), self.csrf)

        handler, form = self._csrf_test_handler(fetch_site=None, fetch_mode=None)
        self.assertEqual(handler._check_csrf(form), self.csrf)

    def test_opaque_origin_rejects_missing_or_untrusted_fetch_metadata_and_host(self):
        cases = (
            {"fetch_site": None},
            {"fetch_mode": None},
            {"fetch_site": "cross-site"},
            {"fetch_mode": "cors"},
            {"referer": None},
            {"referer": "http://attacker.invalid:8501/"},
            {"referer": "http://127.0.0.1:8502/"},
            {"host": "127.0.0.2:8501"},
            {"host": "127.0.0.1:8502"},
            {"bind_host": "0.0.0.0"},
            {"token": "different-token"},
            {"origin": None},
        )
        for options in cases:
            with self.subTest(options=options):
                handler, form = self._csrf_test_handler(**options)
                with redirect_stderr(io.StringIO()), self.assertRaises(RequestError) as raised:
                    handler._check_csrf(form)
                self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)

    def test_opaque_origin_refresh_accepts_only_referer_and_fetch_validated_local_request(self):
        form = {"csrf": self.csrf, "seed": "42", "window": "90"}
        port = self.server.server_port
        accepted = self._post(
            "/refresh", form, origin_value="null", host_value=f"127.0.0.1:{port}",
            referer_value=f"{self.base}/?incident=demo", fetch_site_value="same-origin",
            fetch_mode_value="navigate")
        self.assertEqual(accepted.status, HTTPStatus.OK)

        compatible = self._post(
            "/refresh", form, origin_value="null", host_value=f"127.0.0.1:{port}",
            referer_value=f"{self.base}/?incident=demo")
        self.assertEqual(compatible.status, HTTPStatus.OK)

        rejected_options = (
            {"referer_value": None},
            {"referer_value": "http://attacker.invalid/"},
            {"referer_value": f"http://localhost:{port}/"},
            {"fetch_site_value": "cross-site"},
            {"fetch_mode_value": "cors"},
            {"fetch_site_value": None},
            {"host_value": f"127.0.0.1:{port + 1}"},
        )
        for options in rejected_options:
            with self.subTest(options=options):
                request_options = {
                    "origin_value": "null", "host_value": f"127.0.0.1:{port}",
                    "referer_value": f"{self.base}/", "fetch_site_value": "same-origin",
                    "fetch_mode_value": "navigate",
                }
                request_options.update(options)
                response = self._post("/refresh", form, **request_options)
                self.assertEqual(response.code, HTTPStatus.FORBIDDEN)

        invalid_token = self._post(
            "/refresh", {**form, "csrf": "invalid-token"}, origin_value="null",
            host_value=f"127.0.0.1:{port}", referer_value=f"{self.base}/",
            fetch_site_value="same-origin", fetch_mode_value="navigate")
        self.assertEqual(invalid_token.code, HTTPStatus.FORBIDDEN)

    def test_legitimate_loopback_origins_with_or_without_form_path_are_accepted(self):
        port = self.server.server_port
        for origin_value, host_value in (
            (f"http://127.0.0.1:{port}", f"127.0.0.1:{port}"),
            (f"http://localhost:{port}/decision", f"localhost:{port}"),
        ):
            with self.subTest(origin=origin_value.split(":", 1)[0]):
                response = self._post("/refresh", {"csrf": self.csrf, "seed": "42", "window": "90"},
                                      origin_value=origin_value, host_value=host_value)
                self.assertEqual(response.status, HTTPStatus.OK)

    def test_mismatched_origin_host_or_port_and_missing_origin_are_rejected(self):
        port = self.server.server_port
        mismatched_port = port % 65535 + 1
        form = {"csrf": self.csrf, "seed": "42", "window": "90"}
        cases = [
            {"origin_value": f"http://127.0.0.1:{mismatched_port}"},
            {"origin_value": f"http://127.0.0.1:{port}", "host_value": f"127.0.0.1:{mismatched_port}"},
            {"origin_value": f"http://localhost:{port}", "host_value": f"unrelated.invalid:{port}"},
            {"origin_value": f"http://localhost:{port}", "host_value": f"127.0.0.1:{port}"},
            {"origin": False},
            {"origin_value": f"http://attacker.invalid:{port}", "host_value": f"attacker.invalid:{port}"},
        ]
        for options in cases:
            with self.subTest(options=options):
                response = self._post("/refresh", form, **options)
                self.assertEqual(response.code, HTTPStatus.FORBIDDEN)

    def test_failure_log_contains_only_safe_origin_classifications(self):
        port = self.server.server_port
        response, diagnostic = self._post_with_diagnostics(
            "/refresh", {"csrf": self.csrf, "seed": "42", "window": "90"},
            origin_value=f"https://sensitive-name.invalid:{port}/", host_value=f"sensitive-name.invalid:{port}")
        self.assertEqual(response.code, HTTPStatus.FORBIDDEN)
        self.assertIn("origin[kind=absolute,scheme=https,host=dns,port=nondefault]", diagnostic)
        self.assertIn("host[kind=authority,scheme=http,host=dns,port=nondefault]", diagnostic)
        self.assertIn("referer[kind=missing", diagnostic)
        self.assertNotIn("sensitive-name.invalid", diagnostic)
        self.assertNotIn(self.csrf, diagnostic)

    def test_each_csrf_validation_check_reports_only_its_failed_check_names(self):
        port = self.server.server_port
        valid_form = {"csrf": self.csrf, "seed": "42", "window": "90"}
        cases = [
            ({**valid_form, "csrf": "invalid"}, {"csrf": False}, "cookie_token_format"),
            ({**valid_form, "csrf": "A" * 43}, {}, "cookie_form_token_match"),
            (valid_form, {"origin_value": "null"}, "origin_parse_success"),
            (valid_form, {"host_value": "http://["}, "host_parse_success"),
            (valid_form, {"origin_value": f"http://localhost:{port}",
                          "host_value": f"unrelated.invalid:{port}"}, "authority_match"),
            (valid_form, {"origin_value": f"http://unrelated.invalid:{port}",
                          "host_value": f"unrelated.invalid:{port}"}, "loopback_origin_condition"),
        ]
        for fields, request_options, expected_failure in cases:
            with self.subTest(check=expected_failure):
                response, diagnostic = self._post_with_diagnostics("/refresh", fields, **request_options)
                self.assertEqual(response.code, HTTPStatus.FORBIDDEN)
                self.assertIn(expected_failure, diagnostic)
                self.assertNotIn(self.csrf, diagnostic)
                self.assertNotIn("operator", diagnostic)

    def test_malformed_and_out_of_range_refresh_inputs_are_rejected(self):
        invalid_seed = self._post("/refresh", {"csrf": self.csrf, "seed": "999999999", "window": "90"})
        self.assertEqual(invalid_seed.code, HTTPStatus.BAD_REQUEST)
        malformed = Request(self.base + "/refresh", data=b"not-a-form", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": f"{self.csrf_cookie_name}={self.csrf}",
            "Origin": self.base}, method="POST")
        try:
            self.client.open(malformed, timeout=3)
            self.fail("Expected malformed form to be rejected")
        except HTTPError as error:
            self.assertEqual(error.code, HTTPStatus.BAD_REQUEST)

    def test_decision_requires_explicit_confirmation_and_valid_recommendation(self):
        common = {"csrf": self.csrf, "incident_id": self.incident.incident_id,
                  "action_id": self.recommendation.action_id, "decision": "Approved",
                  "approver": "operator-1"}
        unconfirmed = self._post("/decision", {**common, "confirmed": "no"})
        self.assertEqual(unconfirmed.code, HTTPStatus.BAD_REQUEST)
        malformed = self._post("/decision", {key: value for key, value in common.items()
                                               if key != "approver"} | {"confirmed": "yes"})
        self.assertEqual(malformed.code, HTTPStatus.BAD_REQUEST)
        invalid_decision = self._post("/decision", {**common, "decision": "Execute", "confirmed": "yes"})
        self.assertEqual(invalid_decision.code, HTTPStatus.BAD_REQUEST)
        empty_approver = self._post("/decision", {**common, "approver": "   ", "confirmed": "yes"})
        self.assertEqual(empty_approver.code, HTTPStatus.BAD_REQUEST)
        invalid_action = self._post("/decision", {**common, "action_id": "delete-everything",
                                                    "confirmed": "yes"})
        self.assertEqual(invalid_action.code, HTTPStatus.NOT_FOUND)
        self.assertEqual(self.store.list_approval_history(self.incident.incident_id), [])

    def test_confirmed_decision_persists_and_never_executes(self):
        response = self._post("/decision", {"csrf": self.csrf, "incident_id": self.incident.incident_id,
                                           "action_id": self.recommendation.action_id,
                                           "decision": "Approved", "approver": "operator-1",
                                           "confirmed": "yes"},
                              origin_value=f"http://localhost:{self.server.server_port}",
                              host_value=f"127.0.0.1:{self.server.server_port}")
        # urllib follows the 303 redirect and returns the rendered dashboard.
        self.assertEqual(response.status, HTTPStatus.OK)
        self.assertIn("status=recorded", response.geturl())
        saved = next(item for item in self.store.list_recommendations(self.incident.incident_id)
                     if item.action_id == self.recommendation.action_id)
        self.assertEqual(saved.approval_status, "Approved")
        self.assertEqual(saved.execution_status, "Not executed")
        self.assertEqual(self.store.list_approval_history(self.incident.incident_id)[0]["approver"], "operator-1")
        dashboard = self._get("/?incident=" + self.incident.incident_id)
        self.assertIn("Approval: <b>Approved</b>", dashboard)
        self.assertIn("Execution: <b>Not executed</b>", dashboard)

    def test_valid_rejection_persists_without_executing(self):
        response = self._post("/decision", {"csrf": self.csrf, "incident_id": self.incident.incident_id,
                                           "action_id": self.recommendation.action_id,
                                           "decision": "Rejected", "approver": "reviewer-3",
                                           "confirmed": "yes"})
        self.assertEqual(response.status, HTTPStatus.OK)
        saved = next(item for item in self.store.list_recommendations(self.incident.incident_id)
                     if item.action_id == self.recommendation.action_id)
        self.assertEqual(saved.approval_status, "Rejected")
        self.assertEqual(saved.execution_status, "Not executed")
        self.assertEqual(self.store.list_approval_history(self.incident.incident_id)[0]["decision"], "Rejected")

    def test_repeated_same_seed_refresh_is_idempotent_and_keeps_approval_audit(self):
        decision = self._post("/decision", {"csrf": self.csrf, "incident_id": self.incident.incident_id,
                                            "action_id": self.recommendation.action_id,
                                            "decision": "Approved", "approver": "operator-2",
                                            "confirmed": "yes"})
        self.assertEqual(decision.status, HTTPStatus.OK)
        counts_before = self.store.counts()
        for _ in range(2):
            refreshed = self._post("/refresh", {"csrf": self.csrf, "seed": "42", "window": "90"})
            self.assertEqual(refreshed.status, HTTPStatus.OK)
        self.assertEqual(self.store.counts(), counts_before)
        current = next(item for item in self.store.list_recommendations(self.incident.incident_id)
                       if item.action_id == self.recommendation.action_id)
        self.assertEqual(current.approval_status, "Approved")
        self.assertEqual(current.execution_status, "Not executed")
        self.assertEqual(len(self.store.list_approval_history(self.incident.incident_id)), 1)


if __name__ == "__main__":
    unittest.main()

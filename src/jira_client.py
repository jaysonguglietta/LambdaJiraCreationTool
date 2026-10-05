from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from adf import plain_text
from budget import Budget
from identity import PROPERTY_KEY, Identity


class JiraError(RuntimeError):
    """A sanitized Jira API failure safe to emit to operational logs."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class IdentityReviewRequired(JiraError):
    """A real identity/legacy ambiguity, distinct from a retryable API outage."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise JiraError("Authenticated Jira redirects are forbidden", code)


def validated_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise JiraError("Invalid Jira origin port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in {None, 443}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise JiraError(
            "Jira origin must be an HTTPS hostname without a path, query, or credentials"
        )
    return f"https://{parsed.hostname.lower()}"


@dataclass(frozen=True)
class JiraCredentials:
    base_url: str
    email: str
    api_token: str = field(repr=False)
    identity_key: str = field(default="", repr=False)

    @classmethod
    def from_secret(
        cls, secret: dict[str, object], allowed_host_suffix: str, expected_origin: str | None = None
    ) -> JiraCredentials:
        base_url = str(secret.get("base_url", "")).strip().rstrip("/")
        email = str(secret.get("email", "")).strip()
        api_token = str(secret.get("api_token", "")).strip()
        base_url = validated_origin(base_url)
        if expected_origin and base_url != validated_origin(expected_origin):
            raise JiraError("Jira secret does not match the exact configured origin")
        parsed = urllib.parse.urlparse(base_url)
        suffix = allowed_host_suffix.strip(".").lower()
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise JiraError("Jira base_url must be a credential-free HTTPS URL")
        if not suffix or (host != suffix and not host.endswith(f".{suffix}")):
            raise JiraError("Jira base_url host is outside the configured allowlist")
        if not email or not api_token:
            raise JiraError("Jira secret must contain email and api_token")
        identity_key = str(secret.get("identity_key", "")).strip()
        return cls(base_url=base_url, email=email, api_token=api_token, identity_key=identity_key)


def _jql_string(value: str) -> str:
    cleaned = value.replace("\\", "\\\\").replace('"', '\\"')
    cleaned = "".join(char for char in cleaned if ord(char) >= 32)
    return f'"{cleaned}"'


def _issue_text(issue: dict) -> str:
    fields = issue.get("fields", {})
    description = fields.get("description")
    if isinstance(description, str):
        description_text = description
    else:
        description_text = plain_text(description)
    return f"{fields.get('summary', '')} {description_text}"


class JiraClient:
    def __init__(
        self,
        credentials: JiraCredentials,
        project_key: str,
        *,
        opener: Callable[..., object] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 4,
        budget: Budget | None = None,
        max_response_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.credentials = credentials
        self.project_key = project_key
        validated_origin(credentials.base_url)
        self._opener = (
            opener
            or urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirects()).open
        )
        self._sleep = sleep
        self._max_attempts = max_attempts
        self.budget = budget or Budget(240)
        self.max_response_bytes = max_response_bytes
        encoded = base64.b64encode(f"{credentials.email}:{credentials.api_token}".encode()).decode(
            "ascii"
        )
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "security-jira-automation/2.0",
        }
        self._authorization = f"Basic {encoded}"

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        raw_body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> dict | list:
        if body is not None and raw_body is not None:
            raise ValueError("body and raw_body are mutually exclusive")
        url = f"{self.credentials.base_url}{path}"
        if not path.startswith("/rest/api/3/"):
            raise JiraError("Unsupported Jira API path")
        data = (
            raw_body
            if raw_body is not None
            else (json.dumps(body).encode("utf-8") if body is not None else None)
        )
        headers = dict(self._headers)
        if extra_headers:
            headers.update(extra_headers)
        last_error: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            self.budget.require(5)
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            request.add_unredirected_header("Authorization", self._authorization)
            try:
                with self._opener(
                    request, timeout=min(30, self.budget.remaining() - 1)
                ) as response:
                    status = int(response.status)
                    payload = response.read(self.max_response_bytes + 1)
                    if len(payload) > self.max_response_bytes:
                        raise JiraError("Jira response exceeds the configured byte limit")
                    if status not in expected:
                        raise JiraError(f"Jira {method} {path} returned HTTP {status}")
                    if not payload:
                        return {}
                    try:
                        parsed = json.loads(payload.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise JiraError("Jira returned invalid JSON") from exc
                    if not isinstance(parsed, (dict, list)):
                        raise JiraError("Jira returned an unexpected JSON type")
                    return parsed
            except urllib.error.HTTPError as exc:
                last_error = exc
                ambiguous_create = (
                    method == "POST" and path != "/rest/api/3/search/jql" and exc.code != 429
                )
                retryable = not ambiguous_create and (exc.code == 429 or 500 <= exc.code <= 599)
                if not retryable or attempt == self._max_attempts:
                    request_id = (
                        exc.headers.get("X-Request-Id", "unknown") if exc.headers else "unknown"
                    )
                    exc.close()
                    raise JiraError(
                        f"Jira {method} failed with HTTP {exc.code}; request_id={request_id}",
                        exc.code,
                    ) from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                exc.close()
                delay = (
                    min(int(retry_after[:6]), 15)
                    if retry_after and retry_after.isdigit()
                    else 2 ** (attempt - 1)
                )
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if method == "POST" and path != "/rest/api/3/search/jql":
                    raise JiraError(
                        "Jira mutation response is uncertain; reconcile before retrying"
                    ) from exc
                if attempt == self._max_attempts:
                    raise JiraError(f"Jira {method} {path} failed after retries") from exc
                delay = 2 ** (attempt - 1)
            delay = min(delay, 15)
            self.budget.require(delay + 5)
            self._sleep(delay)
        raise JiraError(f"Jira request failed: {type(last_error).__name__}")

    def preflight(self) -> dict:
        return self._request("GET", "/rest/api/3/myself")

    def search(
        self, jql: str, fields: list[str] | None = None, max_results: int = 50
    ) -> list[dict]:
        body = {
            "jql": jql,
            "fields": fields
            or [
                "summary",
                "description",
                "labels",
                "parent",
                "status",
                "project",
                "issuetype",
                "issuelinks",
                "assignee",
                "duedate",
            ],
            "maxResults": max_results,
        }
        results, tokens = [], set()
        for _ in range(200):
            response = self._request("POST", "/rest/api/3/search/jql", body)
            issues = response.get("issues", [])
            if not isinstance(issues, list):
                raise JiraError("Jira search returned an unexpected response")
            results.extend(issues)
            token = response.get("nextPageToken")
            if not token:
                return results
            if not isinstance(token, str) or token in tokens:
                raise JiraError("Jira search returned a repeated/invalid pagination token")
            tokens.add(token)
            body["nextPageToken"] = token
        raise JiraError("Jira search exceeded its pagination limit")

    def find_epic(self, repository: str, repository_label: str, expected_title: str) -> dict | None:
        # A migrated campaign might be a Task. Discover exact-title candidates
        # without assuming an issue type; the service still requires explicit adoption.
        jql = (
            f"project = {_jql_string(self.project_key)} "
            f"AND labels = {_jql_string(repository_label)} ORDER BY created ASC"
        )
        for issue in self.search(jql):
            fields = issue.get("fields", {})
            if str(fields.get("summary", "")) == expected_title:
                return issue
        if not repository_label.startswith("repo-"):
            return None
        fallback = (
            f"project = {_jql_string(self.project_key)} "
            f"AND summary ~ {_jql_string(repository)} ORDER BY created ASC"
        )
        for issue in self.search(fallback):
            summary = str(issue.get("fields", {}).get("summary", ""))
            if summary == expected_title:
                return issue
        return None

    def find_child(self, repository: str, snyk_id: str, automation_label: str) -> dict | None:
        by_label = (
            f"project = {_jql_string(self.project_key)} "
            f"AND labels = {_jql_string(automation_label)} "
            "ORDER BY created ASC"
        )
        issues = self.search(by_label)
        if issues:
            raise IdentityReviewRequired(
                "Legacy labels require explicit adoption; they cannot establish identity"
            )
        if not automation_label.startswith("snyk-auto-"):
            # Other products have no legacy unlabeled tickets; a text fallback can
            # collide with a Snyk finding or a different product's ID.
            return None
        by_text = (
            f"project = {_jql_string(self.project_key)} AND text ~ {_jql_string(snyk_id)} "
            "ORDER BY created ASC"
        )
        pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])" + re.escape(repository) + r"(?![A-Za-z0-9_.-])", re.IGNORECASE
        )
        for issue in self.search(by_text):
            if not pattern.search(_issue_text(issue)):
                continue
            prop = self.get_property(issue["key"])
            try:
                other = Identity(**prop["identity"]) if prop else None
            except (KeyError, TypeError):
                other = None
            if (
                other
                and other.matches(prop, self.credentials.identity_key)
                and prop.get("jira_key") == issue["key"]
                and other.origin == self.credentials.base_url
                and other.project_id == str(issue.get("fields", {}).get("project", {}).get("id"))
                and (other.source, other.repository, other.finding_id)
                != ("snyk", repository, snyk_id)
            ):
                continue
            raise IdentityReviewRequired(
                "Scoped legacy/missing-label candidate requires adoption or audited restore"
            )
        return None

    def get_issue(self, issue_key: str, fields: list[str] | None = None) -> dict:
        encoded_key = urllib.parse.quote(issue_key, safe="-")
        requested_fields = ",".join(
            fields
            or [
                "summary",
                "description",
                "labels",
                "parent",
                "status",
                "priority",
                "project",
                "issuetype",
                "issuelinks",
                "assignee",
                "duedate",
            ]
        )
        return self._request(
            "GET",
            f"/rest/api/3/issue/{encoded_key}?fields="
            f"{urllib.parse.quote(requested_fields, safe=',')}",
        )

    def try_get_issue(self, issue_key: str) -> dict | None:
        try:
            return self.get_issue(issue_key)
        except JiraError as exc:
            if exc.status_code == 404:
                return None
            raise

    def get_project(self) -> dict:
        return self._request("GET", f"/rest/api/3/project/{urllib.parse.quote(self.project_key)}")

    def get_property(self, key: str) -> dict | None:
        try:
            encoded = urllib.parse.quote(key, safe="-")
            result = self._request("GET", f"/rest/api/3/issue/{encoded}/properties/{PROPERTY_KEY}")
            return result.get("value")
        except JiraError as exc:
            if exc.status_code == 404:
                return None
            raise

    def put_property(self, key: str, value: dict) -> None:
        self._request(
            "PUT", f"/rest/api/3/issue/{key}/properties/{PROPERTY_KEY}", value, expected=(200, 201)
        )

    def find_identity(self, identity: Identity, legacy_labels: list[str]) -> dict | None:
        labels = [identity.label, *legacy_labels]
        jql = (
            f"project = {_jql_string(self.project_key)} AND labels in "
            f"({','.join(_jql_string(label) for label in labels)}) ORDER BY created ASC"
        )
        matches, untrusted = [], []
        for issue in self.search(jql):
            value = self.get_property(issue["key"])
            if (
                identity.matches(value, self.credentials.identity_key)
                and value.get("jira_key") == issue["key"]
            ):
                matches.append(issue)
            else:
                untrusted.append(issue["key"])
        if untrusted or len(matches) > 1:
            raise IdentityReviewRequired(
                "Ambiguous/untrusted ticket candidates; use reviewed adoption/repair"
            )
        return matches[0] if matches else None

    def validate_setup(self, config, custom_fields: dict) -> dict:
        self.create_fields = {}
        self.validated_accounts = set()
        self.preflight()
        project = self.get_project()
        permissions = self._request(
            "GET",
            f"/rest/api/3/mypermissions?projectKey={self.project_key}"
            "&permissions=BROWSE_PROJECTS,CREATE_ISSUES,EDIT_ISSUES,LINK_ISSUES",
        ).get("permissions", {})
        missing = [
            name
            for name in ("BROWSE_PROJECTS", "CREATE_ISSUES", "EDIT_ISSUES", "LINK_ISSUES")
            if not permissions.get(name, {}).get("havePermission")
        ]
        if missing:
            raise JiraError("Missing Jira permissions: " + ", ".join(missing))
        available = {item["name"]: item["id"] for item in project.get("issueTypes", [])}
        for kind, name in (
            ("campaign", config.jira_epic_issue_type),
            ("finding", config.jira_child_issue_type),
        ):
            if name not in available:
                raise JiraError(f"Configured {kind} issue type is unavailable")
            start, fields = 0, []
            while True:
                page = self._request(
                    "GET",
                    f"/rest/api/3/issue/createmeta/{project['id']}/issuetypes/"
                    f"{available[name]}?startAt={start}&maxResults=50",
                )
                values = page.get("values", [])
                fields.extend(values)
                start += len(values)
                if page.get("isLast", start >= page.get("total", start)):
                    break
                if not values or start > 1000:
                    raise JiraError("Invalid create-metadata pagination")
            supplied = {"project", "issuetype", "summary", "description", "labels", "priority"}
            if kind == "finding":
                supplied.update({"assignee", "duedate"})
            supplied.update(custom_fields.get(kind, {}))
            required = [
                item.get("fieldId", item.get("key"))
                for item in fields
                if item.get("required")
                and not item.get("hasDefaultValue")
                and item.get("fieldId", item.get("key")) not in supplied
            ]
            if required:
                raise JiraError(f"Required {kind} fields need configuration: {', '.join(required)}")
            self.create_fields[kind] = fields
        if not config.dry_run_default and len(self.credentials.identity_key) < 32:
            raise JiraError(
                "Live operation requires a separate identity_key of at least 32 characters"
            )
        return {
            "status": "VALIDATED",
            "project_id": str(project["id"]),
            "project_key": project["key"],
            "origin": self.credentials.base_url,
        }

    def validate_payload(self, kind: str, payload: dict) -> None:
        fields = self.create_fields[kind]
        for definition in fields:
            name = definition.get("fieldId", definition.get("key"))
            if (
                definition.get("required")
                and not definition.get("hasDefaultValue")
                and not payload.get(name)
            ):
                raise JiraError(f"Missing required {kind} field: {name}")
            allowed = definition.get("allowedValues", [])
            value = payload.get(name)
            if value and allowed:
                items = value if isinstance(value, list) else [value]
                for item in items:
                    selected = (
                        item.get("id") or item.get("name") or item.get("value")
                        if isinstance(item, dict)
                        else item
                    )
                    choices = {
                        str(v.get(k))
                        for v in allowed
                        if isinstance(v, dict)
                        for k in ("id", "name", "value")
                        if v.get(k) is not None
                    }
                    if choices and str(selected) not in choices:
                        raise JiraError(f"Unsupported configured value for {kind} field {name}")
        supported = {f.get("fieldId", f.get("key")) for f in fields}
        for name in ("assignee", "duedate"):
            if name in payload and name not in supported:
                raise JiraError(f"{name} is not available on the configured create screen")
        account = payload.get("assignee", {}).get("accountId")
        if account and account not in self.validated_accounts:
            query = urllib.parse.urlencode({"project": self.project_key, "accountId": account})
            users = self._request("GET", f"/rest/api/3/user/assignable/search?{query}")
            if not isinstance(users, list) or not any(
                u.get("accountId") == account and u.get("active", True) for u in users
            ):
                raise JiraError("Configured owner is not an active assignable user")
            self.validated_accounts.add(account)

    def transition(self, key: str, transition_id: str) -> None:
        available = self._request("GET", f"/rest/api/3/issue/{key}/transitions")
        if transition_id not in {str(t["id"]) for t in available.get("transitions", [])}:
            raise JiraError("Configured lifecycle transition is not available on this issue")
        self._request(
            "POST",
            f"/rest/api/3/issue/{key}/transitions",
            {"transition": {"id": transition_id}},
            expected=(204,),
        )

    def create_issue(self, fields: dict, properties: list[dict] | None = None) -> dict:
        body = {"fields": fields}
        if properties:
            body["properties"] = properties
        return self._request("POST", "/rest/api/3/issue", body, expected=(201,))

    def update_labels(self, key: str, add: set[str], remove: set[str]) -> None:
        operations = [{"add": label} for label in sorted(add)]
        operations += [{"remove": label} for label in sorted(remove)]
        if operations:
            self._request(
                "PUT",
                f"/rest/api/3/issue/{key}",
                {"update": {"labels": operations}},
                expected=(204,),
            )

    def update_issue(self, issue_key: str, fields: dict) -> None:
        encoded_key = urllib.parse.quote(issue_key, safe="-")
        self._request(
            "PUT",
            f"/rest/api/3/issue/{encoded_key}",
            {"fields": fields},
            expected=(204,),
        )

    def create_issue_link(
        self,
        campaign_key: str,
        child_key: str,
        link_type: str = "Relates",
    ) -> None:
        self._request(
            "POST",
            "/rest/api/3/issueLink",
            {
                "type": {"name": link_type},
                "inwardIssue": {"key": campaign_key},
                "outwardIssue": {"key": child_key},
            },
            expected=(201,),
        )

    def get_attachment_settings(self) -> dict:
        return self._request("GET", "/rest/api/3/attachment/meta")

    def list_attachments(self, issue_key: str) -> list[dict]:
        issue = self.get_issue(issue_key, fields=["attachment"])
        attachments = issue.get("fields", {}).get("attachment", [])
        if not isinstance(attachments, list):
            raise JiraError("Jira returned an unexpected attachment list")
        return attachments

    def upload_attachment(
        self,
        issue_key: str,
        filename: str,
        content_type: str,
        body: bytes,
    ) -> dict:
        safe_name = "".join(
            char if ord(char) >= 32 and char not in {'"', "\\", "/", ";"} else "_"
            for char in filename
        ).strip(" .")
        safe_name = safe_name.encode("ascii", "replace").decode("ascii")[:220] or "attachment"
        boundary = f"----snyk-jira-{uuid.uuid4().hex}"
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("ascii")
        payload = prefix + body + f"\r\n--{boundary}--\r\n".encode("ascii")
        encoded_key = urllib.parse.quote(issue_key, safe="-")
        response = self._request(
            "POST",
            f"/rest/api/3/issue/{encoded_key}/attachments",
            raw_body=payload,
            extra_headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "X-Atlassian-Token": "no-check",
            },
            expected=(200,),
        )
        if not isinstance(response, list) or not response:
            raise JiraError("Jira attachment upload returned an unexpected response")
        return response[0]

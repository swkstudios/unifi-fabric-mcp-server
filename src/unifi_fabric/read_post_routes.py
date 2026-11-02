"""The read-POST allowlist: the exact POSTs that are reads.

A POST is a write. The only exceptions are listed here, in two tables:

* :data:`READ_POST_ROUTES` - the exact (method, route) pairs: queries whose body selects
  what to read and which change no state. Route-exact: method plus a full path template
  whose placeholders match exactly one path segment, never a prefix (``.../stat/session``
  is listed; ``.../stat`` and ``.../stat/sta`` are not).
* :data:`READ_COMMANDS` - the exact (route, command) pairs of the Classic read commands:
  a POST of exactly ``{"cmd": <command>}`` to ``.../api/s/{site}/cmd/<route>``. The same
  routes also carry commands that change state (``cmd/backup`` ``backup``, ``cmd/devmgr``
  ``speedtest``), so a read command is a read only as the pair, never by route or command
  alone. This one table is the read-command list for read-only mode, dry-run, the audit log
  and the write-tool derivation alike.

Only the raw, exact route is a read; anything ambiguous is a write. The raw request path
loses its query once (everything after the first raw ``?``); the rest must equal the
template verbatim: literals case-sensitive and never percent-encoded (``STAT``,
``st%61t``, ``hourly%2Esite``, a trailing slash or a doubled slash is not the route), and
each placeholder one segment that in no decoding round holds ``/``, ``\\``, ``?`` or ``#``
(``%2F``, ``%5C``, ``%3F``, ``%23``, double-encoded too) or is ``.`` / ``..``.

Consumers (one classifier everywhere):

* :func:`unifi_fabric.read_only.is_write_request` - read-only mode (``UNIFI_READ_ONLY``),
  dry-run, the audit log and additive-key stripping. A listed route or read command is a
  read; every other POST/PUT/PATCH/DELETE is a write. The generic connector relay passes
  ``always_write``, so a relayed POST is a write whatever its path and body.
* :func:`post_read` - the ONLY way a typed tool sends a read-POST. It refuses (before any
  request) a POST that is neither a listed route nor a listed read command, so a tool
  cannot be advertised as a read while sending an unlisted POST. ``_read_only_audit``
  treats a ``post_read`` call as a read and every ``client.post`` as a write, so a tool
  that mixes a listed read-POST with any write is still classified a write tool
  (``readOnlyHint: false``), and discovery mode's ``call_read_tool``, ``UNIFI_READ_ONLY``
  and a read-tools-only deployment keep exactly the read tools.

Adding a route: a PR of its own that adds one :class:`ReadPostRoute` with its ``evidence``
(live, on a development controller: the call answered with a query result, and config
collection digests taken before and after are identical; recorded under
the private evidence directory) and a review of its own. Adding a read command: one
:class:`ReadCommand` whose ``evidence`` cites a pinned reference that documents the exact
(route, command) pair as a read.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

if TYPE_CHECKING:
    from .client import UniFiClient
    from .config import APIKeyConfig

#: ``{name}`` in a template: exactly one non-empty path segment without ``/``.
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")

#: Placeholders that hold an enumerated token (``hourly``, ``site``, ``1h``): never
#: percent-encoded and never holding a ``.`` (the ``{interval}.{scope}`` separator).
_ENUM_PLACEHOLDERS = frozenset({"interval", "scope"})

#: Characters a placeholder value may not hold raw: a separator (``/``, ``\\``), a query
#: or fragment start (``?``, ``#``). ``%`` is allowed only in id placeholders and is then
#: judged by its decoded form (:func:`_placeholder_ok`).
_ID_SEGMENT = r"[^/\\?#]+"
_ENUM_SEGMENT = r"[^/\\?#.%]+"

#: Percent-decoding rounds a placeholder value is judged over; a value still changing
#: after them is refused (fail closed).
_DECODE_ROUNDS = 8

#: Characters a placeholder may not hold in ANY decoding round: an encoded separator
#: (``%2F``, ``%5C``) would move the route boundary for an upstream that decodes, and an
#: encoded ``?`` / ``#`` would end the path there.
_FORBIDDEN_DECODED = frozenset("/\\?#")


def _placeholder_ok(name: str, value: str) -> bool:
    """True when ``value`` (one raw path segment) is an unambiguous placeholder value."""
    seen = value
    for _ in range(_DECODE_ROUNDS):
        if _FORBIDDEN_DECODED.intersection(seen) or seen in (".", ".."):
            return False
        if name in _ENUM_PLACEHOLDERS and "." in seen:
            return False
        decoded = unquote(seen)
        if decoded == seen:
            return True
        seen = decoded
    return False


def _compile(template: str) -> tuple[re.Pattern[str], tuple[str, ...]]:
    """The raw-path pattern of ``template`` and its placeholder names, in order.

    Literal characters match only themselves, raw and case-sensitive: any spelling
    variant (``STAT``, ``st%61t``, ``hourly%2Esite``) is not the route.
    """
    parts: list[str] = []
    names: list[str] = []
    pos = 0
    for match in _PLACEHOLDER_RE.finditer(template):
        parts.append(re.escape(template[pos : match.start()]))
        name = match.group(1)
        names.append(name)
        parts.append(f"({_ENUM_SEGMENT if name in _ENUM_PLACEHOLDERS else _ID_SEGMENT})")
        pos = match.end()
    parts.append(re.escape(template[pos:]))
    return re.compile("^" + "".join(parts) + r"\Z"), tuple(names)


def split_query(path: str) -> str:
    """``path`` without its query string: everything before the FIRST raw ``?``.

    The only place a read-POST path loses its query. It runs once, on the raw path the
    request will carry; nothing downstream splits again, so an encoded ``?`` (``%3F``,
    ``%253F``) stays in the path and can never turn a longer path into a listed route.
    """
    return path.split("?", 1)[0]


@dataclass(frozen=True)
class ReadPostRoute:
    """One allowlisted read-POST.

    Attributes:
        name: Stable id (test ids, docs).
        method: Always ``POST`` (the other methods are never reads by this list).
        template: The full request-path template, placeholders in braces.
        tools: The typed tools that send it.
        evidence: The live no-state-effect evidence (the records are kept privately, keyed
            by ``name``).
        sample: A concrete path for samples and a post-deploy refusal check (synthetic ids).
    """

    name: str
    method: str
    template: str
    tools: frozenset[str]
    evidence: tuple[str, ...]
    sample: str
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _names: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.method != "POST":
            raise ValueError(f"{self.name}: only POST routes are listed")
        pattern, names = _compile(self.template)
        object.__setattr__(self, "_pattern", pattern)
        object.__setattr__(self, "_names", names)

    def matches(self, method: str, bare_path: str) -> bool:
        """True when ``method`` + ``bare_path`` is exactly this route.

        ``bare_path`` is the raw request path with its query already removed by
        :func:`split_query` (no second split here: a ``?`` left in it is not the route).
        Literal segments match raw and exactly; each placeholder is one segment whose
        value, in every percent-decoding round, holds no ``/``, ``\\``, ``?`` or ``#`` and
        is not ``.`` / ``..`` (:func:`_placeholder_ok`).
        """
        if not isinstance(method, str) or method.strip().upper() != self.method:
            return False
        if not isinstance(bare_path, str):
            return False
        match = self._pattern.match(bare_path)
        if match is None:
            return False
        return all(
            _placeholder_ok(name, value)
            for name, value in zip(self._names, match.groups(), strict=True)
        )


_CONSOLE = "/v1/connector/consoles/{console}/proxy"
_SAMPLE_CONSOLE = (
    "/v1/connector/consoles/"
    "000000000000000000000000000000000000000000000000000000FA0001:0000000001/proxy"
)
_LIVE = (
    "live 2026-10-12 on a development controller, read-only process: HTTP 200, "
    "8/8 configuration collection digests unchanged"
)

#: The allowlist. One entry per exact route; each carries its evidence.
# Candidate routes deliberately remain inactive until each named recorder recipe produces
# a private live evidence record.  Do not uncomment a route without that record.
# pending live evidence traffic-flows-export-v1
# ReadPostRoute(
#     name="network-v2-traffic-flows-export", method="POST",
#     template=_CONSOLE + "/network/v2/api/site/{site}/traffic-flows/export",
#     tools=frozenset({"export_traffic_flows"}), evidence=(),
#     sample=_SAMPLE_CONSOLE + "/network/v2/api/site/default/traffic-flows/export",
# )
# pending live evidence app-traffic-rate-v1
# ReadPostRoute(
#     name="network-v2-app-traffic-rate", method="POST",
#     template=_CONSOLE + "/network/v2/api/site/{site}/app-traffic-rate",
#     tools=frozenset({"query_app_traffic_rates"}), evidence=(),
#     sample=_SAMPLE_CONSOLE + "/network/v2/api/site/default/app-traffic-rate",
# )
# pending live evidence proav-multicast-v1
# ReadPostRoute(
#     name="network-v2-multicast-insights-clients", method="POST",
#     template=_CONSOLE + "/network/v2/api/site/{site}/insights/multicast/clients",
#     tools=frozenset({"get_multicast_insights"}), evidence=(),
#     sample=_SAMPLE_CONSOLE + "/network/v2/api/site/default/insights/multicast/clients",
# )
# pending live evidence proav-multicast-history-v1
# ReadPostRoute(
#     name="network-v2-multicast-insights-history", method="POST",
#     template=_CONSOLE + "/network/v2/api/site/{site}/insights/multicast/history",
#     tools=frozenset({"get_multicast_insights"}), evidence=(),
#     sample=_SAMPLE_CONSOLE + "/network/v2/api/site/default/insights/multicast/history",
# )
# pending live evidence protect-recognition-search-v1
# ReadPostRoute(
#     name="protect-recognition-search", method="POST",
#     template=_CONSOLE + "/protect/api/recognition/recognize-image",
#     tools=frozenset({"recognize_image"}), evidence=(),
#     sample=_SAMPLE_CONSOLE + "/protect/api/recognition/recognize-image",
# )

READ_POST_ROUTES: tuple[ReadPostRoute, ...] = (
    ReadPostRoute(
        name="network-v2-traffic-flows",
        method="POST",
        template=_CONSOLE + "/network/v2/api/site/{site}/traffic-flows",
        tools=frozenset({"query_traffic_flows"}),
        evidence=(
            "live 2026-10-26 on a development controller: paged query HTTP 200, "
            "8/8 configuration collection digests unchanged; pageSize 5000 accepted, "
            "larger pages answered HTTP 400; 215000 flows drained before HTTP 408",
        ),
        sample=_SAMPLE_CONSOLE + "/network/v2/api/site/default/traffic-flows",
    ),
    ReadPostRoute(
        name="network-classic-stat-session",
        method="POST",
        template=_CONSOLE + "/network/api/s/{site}/stat/session",
        tools=frozenset({"list_client_sessions"}),
        evidence=(_LIVE,),
        sample=_SAMPLE_CONSOLE + "/network/api/s/default/stat/session",
    ),
    ReadPostRoute(
        name="network-classic-stat-report",
        method="POST",
        template=_CONSOLE + "/network/api/s/{site}/stat/report/{interval}.{scope}",
        tools=frozenset({"get_historical_stats"}),
        evidence=(_LIVE, "interval and scope sets probed live 2026-10-10"),
        sample=_SAMPLE_CONSOLE + "/network/api/s/default/stat/report/hourly.site",
    ),
    ReadPostRoute(
        name="site-manager-isp-metrics-query",
        method="POST",
        template="/v1/isp-metrics/{interval}/query",
        tools=frozenset({"query_isp_metrics"}),
        evidence=(_LIVE,),
        sample="/v1/isp-metrics/1h/query",
    ),
)

#: POSTs a read-only deployment must refuse: near misses of the listed routes and
#: read-looking routes that are not listed (still writes until their own allowlist PR).
NOT_LISTED_SAMPLES: tuple[str, ...] = (
    _SAMPLE_CONSOLE + "/network/api/s/default/stat",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/sta",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session/extra",
    _SAMPLE_CONSOLE + "/network/api/s/default/cmd/stat",
    _SAMPLE_CONSOLE + "/network/v2/api/sites/overview",
    _SAMPLE_CONSOLE + "/network/v2/api/site/default/system-log/all",
    _SAMPLE_CONSOLE + "/protect/api/stat/session",
    "/v1/isp-metrics/1h",
    "/v1/isp-metrics/1h/query/extra",
    # Only the raw, exact route is a read: case variants, doubled and trailing slashes,
    # percent-encoded literals, an encoded ? or # (single or double), a dot segment or an
    # encoded separator in a placeholder are all writes.
    _SAMPLE_CONSOLE + "/network/api/s/default/STAT/session",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/Session",
    _SAMPLE_CONSOLE + "/network/api/s/default//stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session/",
    _SAMPLE_CONSOLE + "/network/api/s/default/st%61t/session",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session%3F",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session%3Fx=1",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session%253Fx=1",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/session%23x",
    _SAMPLE_CONSOLE + "/network/api/s/default%3F/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/default%23/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/../stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/%2e%2e/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/%252e%252e/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/de%2Ffault/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/de%252Ffault/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/de%5Cfault/stat/session",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/report/hourly%2Esite",
    _SAMPLE_CONSOLE + "/network/api/s/default/stat/report/hourly.si%74e",
    "/v1/connector/consoles/../proxy/network/api/s/default/stat/session",
    "/v1/connector/consoles/%2e%2e/proxy/network/api/s/default/stat/session",
    "/v1/connector/consoles/a%2Fb/proxy/network/api/s/default/stat/session",
    "/V1/isp-metrics/1h/query",
    "/v1/isp-metrics/1h/Query",
    "/v1//isp-metrics/1h/query",
    "/v1/isp-metrics/1h/query/",
    "/v1/isp-metrics/1h/qu%65ry",
    "/v1/isp-metrics/1h/query%3F",
    "/v1/isp-metrics/1h/query%253Fx",
    "/v1/isp-metrics/1h/query%23x",
    "/v1/isp-metrics/%31h/query",
    "/v1/isp-metrics/1h%2Fx/query",
)


def _command_token(value: str) -> bool:
    """True when ``value`` is lowercase ASCII words joined by single hyphens."""
    words = value.split("-") if isinstance(value, str) else []
    return bool(words) and all(w.isascii() and w.isalpha() and w.islower() for w in words)


#: The pinned references that document each read command.
_ART_OF_WIFI = (
    "Art-of-WiFi/UniFi-API-client@8d04134ca72d3994592c8ce7cb032b67bc684290 src/Client.php"
)
_UBNTWIKI = "ubntwiki.com UniFi Controller API, Callable commands table"
_LIVE_COMMAND = "live on a development controller: HTTP 200, metadata only"


@dataclass(frozen=True)
class ReadCommand:
    """One Classic read command: the exact (route, command) pair.

    A Classic command is a POST of ``{"cmd": <command>}`` to
    ``/v1/connector/consoles/{console}/proxy/network/api/s/{site}/cmd/<route>``. A request
    is this read command only when all three hold: the method is POST; the raw path, its
    query split off once (:func:`split_query`), is the route exactly, under the same
    raw-path rules as :class:`ReadPostRoute` (literals raw and case-sensitive, each
    placeholder one unambiguous segment); and the JSON body is exactly ``{"cmd": command}``
    (a ``dict`` with no other key, the command a ``str`` equal to ``command``).

    Attributes:
        route: The command route (the last path segment), for example ``backup``.
        command: The ``cmd`` value, for example ``list-backups``.
        tools: The typed tools that send it.
        evidence: Where the pinned references document it as a read, and the live check.
    """

    route: str
    command: str
    tools: frozenset[str]
    evidence: tuple[str, ...]
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _names: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not (_command_token(self.route) and _command_token(self.command)):
            raise ValueError(
                f"{self.route!r} {self.command!r}: a read command's route and command are "
                "lowercase words joined by hyphens"
            )
        pattern, names = _compile(self.template)
        object.__setattr__(self, "_pattern", pattern)
        object.__setattr__(self, "_names", names)

    @property
    def name(self) -> str:
        """Stable id (test ids, docs)."""
        return f"network-classic-cmd-{self.route}-{self.command}"

    @property
    def template(self) -> str:
        """The full request-path template of the command route."""
        return _CONSOLE + "/network/api/s/{site}/cmd/" + self.route

    @property
    def sample(self) -> str:
        """A concrete path with synthetic ids."""
        return _SAMPLE_CONSOLE + "/network/api/s/default/cmd/" + self.route

    @property
    def body(self) -> dict[str, str]:
        """The one body this read command sends."""
        return {"cmd": self.command}

    def matches(self, method: str, bare_path: str, body: Any) -> bool:
        """True when ``method`` + ``bare_path`` + ``body`` is exactly this read command.

        ``bare_path`` is the raw request path with its query already removed by
        :func:`split_query`, judged exactly as :meth:`ReadPostRoute.matches` judges it.
        """
        if not isinstance(method, str) or method.strip().upper() != "POST":
            return False
        if type(body) is not dict or len(body) != 1:
            return False
        command = body.get("cmd")
        if type(command) is not str or command != self.command:
            return False
        if not isinstance(bare_path, str):
            return False
        match = self._pattern.match(bare_path)
        if match is None:
            return False
        return all(
            _placeholder_ok(name, value)
            for name, value in zip(self._names, match.groups(), strict=True)
        )


#: The read commands. One entry per exact (route, command) pair; each cites the pinned
#: reference that documents it as a read. No other command on these routes is a read.
READ_COMMANDS: tuple[ReadCommand, ...] = (
    ReadCommand(
        route="firmware",
        command="list-available",
        tools=frozenset({"list_device_firmware"}),
        evidence=(
            f"{_ART_OF_WIFI} list_firmware('available'): 'Fetch firmware versions'",
            _LIVE_COMMAND,
        ),
    ),
    ReadCommand(
        route="firmware",
        command="list-cached",
        tools=frozenset({"list_device_firmware"}),
        evidence=(
            f"{_ART_OF_WIFI} list_firmware('cached'): 'Fetch firmware versions'",
            _LIVE_COMMAND,
        ),
    ),
    ReadCommand(
        route="backup",
        command="list-backups",
        tools=frozenset({"list_backups"}),
        evidence=(
            f"{_ART_OF_WIFI} list_backups(): 'Fetch auto backups'",
            f"{_UBNTWIKI}: backup list-backups, 'list of autobackup files'",
            _LIVE_COMMAND,
        ),
    ),
    ReadCommand(
        route="devmgr",
        command="speedtest-status",
        tools=frozenset({"get_speedtest_status"}),
        evidence=(
            f"{_UBNTWIKI}: devmgr speedtest-status, 'get the current state of the speed test'",
            _LIVE_COMMAND,
        ),
    ),
)


def read_command(method: str, path: str, body: Any) -> ReadCommand | None:
    """The :data:`READ_COMMANDS` entry for ``method`` + the raw ``path`` + ``body``, or None.

    ``path`` is exactly what the request will carry; its query is split off once
    (:func:`split_query`), as for :func:`read_post_route`.
    """
    if not isinstance(path, str):
        return None
    bare = split_query(path)
    for command in READ_COMMANDS:
        if command.matches(method, bare, body):
            return command
    return None


def read_post_route(method: str, path: str) -> ReadPostRoute | None:
    """The allowlist entry for ``method`` + the raw request ``path``, or None.

    ``path`` is exactly what the request will carry (never a decoded form): its query is
    split off once (:func:`split_query`) and the rest must be a listed route verbatim.
    The write classifier (:func:`unifi_fabric.read_only.is_write_request`) and
    :func:`post_read` both decide here on the same raw path, so they never disagree.
    """
    if not isinstance(path, str):
        return None
    bare = split_query(path)
    for route in READ_POST_ROUTES:
        if route.matches(method, bare):
            return route
    return None


def is_read_post(method: str, path: str, body: Any = None) -> bool:
    """True when ``method`` + ``path`` (+ ``body``) is an allowlisted read-POST.

    A listed route (:data:`READ_POST_ROUTES`) is a read whatever its body; a command route
    is a read only with exactly a listed read command's body (:data:`READ_COMMANDS`).
    """
    return read_post_route(method, path) is not None or read_command(method, path, body) is not None


def refusal_samples() -> list[dict[str, str]]:
    """``[{method, path, expect}]`` for a read-only deployment's post-deploy check.

    ``expect`` is ``read`` for every allowlisted route (it must NOT be refused under
    ``UNIFI_READ_ONLY``) and ``refused`` for every not-listed sample (it must be refused
    before any upstream call). Paths carry synthetic ids only.

    ``READ_COMMANDS`` are not sampled: a read command is a read only with its exact
    ``{"cmd": ...}`` body, and these samples carry no body, so a bodiless POST to a
    ``cmd/<route>`` path is a write and would be refused.
    """
    out = [{"method": r.method, "path": r.sample, "expect": "read"} for r in READ_POST_ROUTES]
    out += [{"method": "POST", "path": p, "expect": "refused"} for p in NOT_LISTED_SAMPLES]
    return out


def read_post[F: Callable[..., Any]](fn: F) -> F:
    """Mark ``fn`` as the read-POST sender (``_read_only_audit`` treats its calls as reads)."""
    fn.__unifi_read_post__ = True  # type: ignore[attr-defined]
    return fn


@read_post
async def post_read(
    client: UniFiClient,
    path: str,
    /,
    *,
    key: APIKeyConfig | None = None,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    """Send an allowlisted read-POST and return the decoded body.

    Raises ``ValueError`` before any request when ``path`` and ``json`` are neither an
    allowlisted route nor a listed read command: a typed tool may only send listed
    read-POSTs through this function.
    """
    # The raw path and body this call sends, judged by the same function (and the same
    # single query split) as the client's write classifier.
    if not is_read_post("POST", path, json):
        raise ValueError(
            f"POST {path} is not on the read-POST allowlist (read_post_routes.READ_POST_ROUTES "
            "or READ_COMMANDS); send it with client.post as a write, or add the route with "
            "live evidence"
        )
    if params is not None:
        return await client.post(path, key=key, json=json, params=params)
    return await client.post(path, key=key, json=json)

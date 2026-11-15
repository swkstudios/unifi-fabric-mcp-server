"""The closed vocabulary of an audit record: the path, the reason and the route template.

Every value here comes from a fixed list or a validated shape, so nothing a caller typed
or an upstream returned reaches an audit line as free text.

* :func:`mask_path` masks a path segment by default. A segment stays only when it is a
  route word from the generated route manifest, a validated identifier shape, or a site or
  console in its own position; anything else is :data:`PATH_MASK`. Masking therefore does
  not depend on a route having been registered as carrying a credential: a credential in
  a path segment on an unknown route is masked like any other unknown value.
  ``route_secrets`` still lists the routes whose identifier-shaped segment is itself a
  credential (a UUID share token); the caller scrubs those values first.
* :func:`reason_code` maps a refusal reason to :data:`REASON_CODES`, a known deny token,
  or ``other``.
* :func:`route_template` names the route of a known tool as ``family.resource.verb``.
"""

from __future__ import annotations

import re
import uuid
from functools import lru_cache

from .catalog.membership import family_index
from .macs import is_mac

#: Written in place of a path segment that is not a known word or identifier.
PATH_MASK = "***"

#: Route words of the relay namespaces and the connector prefix: valid even before the
#: first manifest route uses them.
_NAMESPACE_WORDS = frozenset(
    {
        "access",
        "api",
        "connector",
        "consoles",
        "ea",
        "hosts",
        "innerspace",
        "integration",
        "network",
        "protect",
        "proxy",
        "s",
        "site",
        "sites",
        "v1",
        "v2",
        # Built at run time from a boolean, so the manifest's source scan cannot see them.
        "enable-control",
        "disable-control",
    }
)

#: Identifier shapes that are not credentials besides a UUID and a MAC (checked by
#: :func:`_is_identifier`): an ObjectId, a small integer (a port index, a slot) and an
#: IPv4 address.
_IDENTIFIER = re.compile(r"[0-9a-f]{24}|[0-9]{1,6}|[0-9]{1,3}(?:\.[0-9]{1,3}){3}")


def _is_identifier(segment: str) -> bool:
    """An ObjectId, UUID, MAC (the one MAC rule, :mod:`unifi_fabric.macs`), small number
    or IPv4 address."""
    if _IDENTIFIER.fullmatch(segment) or is_mac(segment):
        return True
    if len(segment) != 36:
        return False
    try:
        return str(uuid.UUID(segment)) == segment.lower()
    except ValueError:
        return False


#: A Classic site slug: ``default`` or the short generated name.
_SITE_SLUG = re.compile(r"[a-z0-9]{1,12}")
#: A console id, which the server resolves before it builds the path.
_CONSOLE_ID = re.compile(r"[A-Za-z0-9._:-]{1,96}")
_PLACEHOLDERS = frozenset({"{site}", "{site_id}"})


@lru_cache(maxsize=1)
def _route_words() -> frozenset[str]:
    """Every literal segment of the generated route manifest, plus the namespace words."""
    from .generated_api_facts.route_manifest import MANIFEST

    words = set(_NAMESPACE_WORDS)
    for routes in MANIFEST["tools"].values():
        for route in routes:
            for segment in (route.get("path") or "").split("/"):
                if segment and "{" not in segment:
                    words.add(segment)
    return frozenset(words)


#: The fixed prefixes that hold a console or host id, and the tails after ``proxy/<app>``
#: that hold a site. Anywhere else, the same words protect nothing.
_CONSOLE_PREFIX = ["v1", "connector", "consoles"]
_HOST_PREFIXES = (["v1", "hosts"], ["ea", "hosts"])
_SITE_MANAGER_SITES = ["v1", "sites"]
_APPS = frozenset({"network", "protect", "access", "innerspace"})
_SITE_TAILS = (
    ["api", "s"],
    ["api", "site"],
    ["v2", "api", "site"],
    ["integration", "v1", "sites"],
    ["v1", "sites"],
)


def _positional_ids(segments: list[str], *, relay: bool) -> set[int]:
    """Indexes of the console, host and site segments, by their fixed positions only.

    A relay path is the caller's text, so it never holds a console or host position; only
    the server-built path does. A site counts once, directly after ``proxy/<app>`` (or at
    the start of a relay-relative path).
    """
    kept: set[int] = set()
    absolute = bool(segments) and segments[0] == ""
    start = 1 if absolute else 0
    tail = segments[start:]
    app: int | None = None
    if absolute and not relay:
        if tail[:3] == _CONSOLE_PREFIX and len(tail) > 3:
            if _CONSOLE_ID.fullmatch(tail[3]):
                kept.add(start + 3)
            if tail[4:5] == ["proxy"]:
                app = start + 5
        elif tail[:2] in _HOST_PREFIXES and len(tail) > 2:
            if _CONSOLE_ID.fullmatch(tail[2]):
                kept.add(start + 2)
        elif tail[:2] == _SITE_MANAGER_SITES and len(tail) > 2:
            if _SITE_SLUG.fullmatch(tail[2]):
                kept.add(start + 2)
    if app is None and tail[:1] == ["proxy"]:
        app = start + 1
    if app is None and (relay or not absolute):
        app = start
    if app is not None and app < len(segments) and segments[app] in _APPS:
        for shape in _SITE_TAILS:
            end = app + 1 + len(shape)
            if segments[app + 1 : end] == shape and end < len(segments):
                if _SITE_SLUG.fullmatch(segments[end]):
                    kept.add(end)
                break
    return kept


def mask_path(path: str, *, relay: bool = False) -> str:
    """``path`` with every segment that is not a known word or identifier masked.

    ``relay`` marks a caller-supplied relay path, as opposed to the path the server built.
    """
    words = _route_words()
    segments = path.split("/")
    positional = _positional_ids(segments, relay=relay)
    return "/".join(
        segment
        if (
            not segment
            or segment in words
            or segment in _PLACEHOLDERS
            or _is_identifier(segment)
            or index in positional
        )
        else PATH_MASK
        for index, segment in enumerate(segments)
    )


# ------------------------------------------------------------------------------ reasons

#: Reasons that were free text, now codes.
UNSAFE_PATH = "unsafe_path"
MASKED_BODY = "masked_body"
#: A reason outside the list. Its text goes to the server log under the record's ``ref``.
OTHER_REASON = "other"

#: Reasons this module owns. :func:`reason_code` also accepts the gate names and refusal
#: codes the policy modules define, and a ``family:<id>=deny`` or ``tool:<name>=deny``
#: token naming a known family or tool.
REASON_CODES = (UNSAFE_PATH, MASKED_BODY, "empty_update", "write_denied", OTHER_REASON)

_DENY_TOKEN = re.compile(r"(family|tool):([A-Za-z0-9_-]+)=deny")


def _gate_reasons() -> frozenset[str]:
    """Gate names and refusal codes owned by other modules, read when first needed."""
    from . import header_credentials as hc
    from . import policy
    from .request_policy import sp
    from .switches import CONNECTOR_WRITE_TOKEN, WRITE_EXCEPTIONS_ENV, WRITE_POLICY_ENV

    return frozenset(
        {
            WRITE_POLICY_ENV,
            WRITE_EXCEPTIONS_ENV,
            CONNECTOR_WRITE_TOKEN,
            policy.WRITE_POLICY_HEADER,
            hc.INVALID_POLICY_HEADER,
            *sp.REFUSAL_CODES,
        }
    )


def reason_code(reason: str) -> tuple[str, str | None]:
    """``reason`` as a closed code, and the text to log when it was not one."""
    if reason in REASON_CODES or reason in _gate_reasons():
        return reason, None
    token = _DENY_TOKEN.fullmatch(reason)
    if token is not None:
        kind, name = token.groups()
        families = family_index()
        if name in (families if kind == "tool" else set(families.values())):
            return reason, None
    return OTHER_REASON, reason


# ------------------------------------------------------------------------ route templates

#: Words that end a tool name when the name is not verb-first (``siren_play``).
_TRAILING_VERBS = frozenset({"play", "stop", "start", "home", "output", "trigger"})
_LEADING_VERBS = frozenset(
    """
    accept acknowledge activate add adopt allow analyze apply approve assign attach
    authorize batch block bulk calibrate cancel check clean clear clone collect commission
    compare configure connect control create delete
    detach disable disconnect enable enhance enroll exclude execute export extend forget
    generate get hide import link list locate manage mark merge migrate move patch play
    preview provision query read readopt reboot recognize reconnect recover refresh
    reformat remove rename reorder
    replace report resend reset restart restore resume retry revoke run search send set
    start stop suggest suspend test transfer transform trigger turn unadopt unblock unpair
    update upgrade upload verify
    """.split()
)


def _plural(word: str) -> str:
    if word.endswith("s"):
        return word
    if word.endswith("y") and word[-2:-1] not in set("aeiou"):
        return word[:-1] + "ies"
    return word + "s"


def route_template(tool: str | None) -> str | None:
    """``family.resource.verb`` of a known tool, else ``None``.

    The vocabulary is the typed tool list, so an unknown name (a future tool, a caller
    typo) yields no template instead of echoing the name.
    """
    family = family_index().get(tool) if tool else None
    if family is None or tool is None:
        return None
    if tool.startswith("fabric_connector_"):
        return f"connector.relay.{tool.rsplit('_', 1)[-1]}"
    words = tool.split("_")
    if words[0] in _LEADING_VERBS and len(words) > 1:
        verb, noun = words[0], words[1:]
    elif words[-1] in _TRAILING_VERBS and len(words) > 1:
        verb, noun = words[-1], words[:-1]
    else:
        verb, noun = "call", words
    while noun[:1] == [family] and len(noun) > 1:
        noun = noun[1:]
    if verb != "call":
        noun = [*noun[:-1], _plural(noun[-1])]
    return f"{family}.{'_'.join(noun)}.{verb}"

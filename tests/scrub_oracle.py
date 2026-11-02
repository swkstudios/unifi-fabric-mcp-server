"""G1-G4 reference: uncapped sequential BFS, stdlib token decoding, source spans; plus the
SPEC-V3-1 bound predicate (``bound``) computed by its own BFS to depth 9, and its regional
form (``regions``, ``regional_bound``, ``regional_components``): the same predicate per
G2 region, the regions found by a plain character scan and a brute-force join test over
the forms (no product code)."""

from __future__ import annotations

import codecs
import html
import re
import warnings
from array import array
from functools import lru_cache
from struct import Struct
from urllib.parse import unquote_to_bytes

from unifi_fabric.secret_scrub import _fragments, secret_forms

WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
PATTERNS = (
    re.compile(r"%(?:u[0-9a-fA-F]{4}|[0-9a-fA-F]{2})"),
    re.compile(r"&(?:#[0-9]+;|#[xX][0-9a-fA-F]+;|[A-Za-z][A-Za-z0-9]{0,30};)"),
    re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|[abfnrtv\\'\"/])"),
)


def token_decode(token: str) -> str | None:
    if token.startswith("%u"):
        return chr(int(token[2:], 16))
    if token.startswith("%"):
        return unquote_to_bytes(token).decode("latin-1")
    if token.startswith("&"):
        decoded = html.unescape(token)
        return None if decoded == token else decoded
    if token == r"\/":
        return "/"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return codecs.decode(token, "unicode_escape")
    except UnicodeDecodeError:
        return None


def decode_view(view, kind):
    text, spans = view
    parts, mapped = [], []
    pos = 0
    for match in PATTERNS[kind].finditer(text):
        decoded = token_decode(match.group())
        if decoded is None:
            continue
        a, b = match.span()
        parts.extend((text[pos:a], decoded))
        mapped.extend(spans[pos:a])
        mapped.extend([(spans[a][0], spans[b - 1][1])] * len(decoded))
        pos = b
    parts.append(text[pos:])
    mapped.extend(spans[pos:])
    return "".join(parts), tuple(mapped)


def views(text):
    raw = text, tuple((i, i + 1) for i in range(len(text)))
    pending, seen = [(raw, 0)], {raw}
    for view, depth in pending:
        yield view
        if depth == 8:
            continue
        for kind in range(3):
            decoded = decode_view(view, kind)
            if decoded not in seen:
                seen.add(decoded)
                pending.append((decoded, depth + 1))


COMPONENT = re.compile(r"[A-Za-z0-9#;%\\&]+")

#: SPEC-V3 view bound N, per region (never scaled by text size).
VIEW_LIMIT = 128


def _packed_decoder(text):
    """Exact oracle source spans stored as two unsigned offsets per character.

    Count-only AT4 callers need the entire closure for exact deduplication but
    never inspect individual spans. Keep the same independent BFS and decoder;
    replace the tuple/int object graph with immutable bytes for those callers.
    """
    narrow = len(text) <= 0xFFFFFFFF
    code = next(code for code in "IL" if array(code).itemsize == 4) if narrow else "Q"
    pair = Struct("=II" if narrow else "=QQ")
    width = pair.size
    raw_spans = array(
        code, (value for pos in range(len(text)) for value in (pos, pos + 1))
    ).tobytes()
    decode_token = lru_cache(maxsize=8192)(token_decode)

    def decode(view, kind):
        current, spans = view
        parts, mapped = [], bytearray()
        pos = 0
        for match in PATTERNS[kind].finditer(current):
            token = match.group()
            decoded = decode_token(token) if len(token) <= 16 else token_decode(token)
            if decoded is None:
                continue
            a, b = match.span()
            parts.extend((current[pos:a], decoded))
            mapped.extend(spans[pos * width : a * width])
            first = pair.unpack_from(spans, a * width)[0]
            last = pair.unpack_from(spans, (b - 1) * width)[1]
            mapped.extend(pair.pack(first, last) * len(decoded))
            pos = b
        parts.append(current[pos:])
        mapped.extend(spans[pos * width :])
        return "".join(parts), bytes(mapped)

    return (text, raw_spans), decode


def closure(text, limit=None, *, packed=False):
    """SPEC-V3-1, computed independently of the product: ``(bound, first_views)``.

    BFS over the three families in a fixed order, dedup on text+offsets. ``bound`` is True
    iff |C_8| > ``limit`` (early exit at the (limit+1)th distinct view) or C_9 != C_8 (a
    depth-8 view decodes to a view not in C_8). ``first_views`` are the first
    min(|C_8|, ``limit``) views in BFS order (the ones a bounded enumeration holds).
    ``limit`` defaults to the SPEC-V3 bound N = 128."""
    if limit is None:
        limit = VIEW_LIMIT
    if packed:
        raw, decode = _packed_decoder(text)
    else:
        raw = text, tuple((i, i + 1) for i in range(len(text)))
        decode = decode_view
    level, seen, ordered = [raw], {raw}, [raw]
    for depth in range(9):
        following = []
        for view in level:
            for kind in range(3):
                decoded = decode(view, kind)
                if decoded in seen:
                    continue
                if depth == 8 or len(seen) == limit:
                    return True, ordered
                seen.add(decoded)
                ordered.append(decoded)
                following.append(decoded)
        if not following:
            break
        level = following
    return False, ordered


def bound(text):
    """SPEC-V3-1 bound(text) := |C_8| > 128 OR C_9 != C_8, over the whole text (one
    region, or the bound of a text whose regions are judged by :func:`regional_bound`)."""
    return closure(text)[0]


def view_count(text, limit=128):
    """N(text): the number of distinct decoded views (raw included) that a G2 enumeration
    bounded at ``limit`` views and depth 8 holds, counted by the oracle's own BFS
    (``closure``), never read from product internals. Equals ``limit`` when the N bound
    is reached (the saturation precondition of the AT4 "mixed" family)."""
    return len(closure(text, limit, packed=True)[1])


def closure_size(text, cap=4096):
    """``(|C_8|, C_9 == C_8)`` with the N limit raised to ``cap`` (V3-3 fixture search).

    On a depth hit or a natural end every view of C_8 has been enumerated; at ``cap``
    views the count is a lower bound and the second item is False."""
    hit, ordered = closure(text, limit=cap)
    return len(ordered), not hit


def bound_components(text, limit=None):
    """G5 for AT2(ii), computed by the oracle's own enumeration: every escape component
    (maximal [A-Za-z0-9#;%\\\\&] run holding an introducer), mapped to source, of each
    view AT the bound -- a view one of whose decodings is a new view that the bounds
    exclude (a (limit+1)th view, or a view past depth 8). Empty when no bound is hit.
    ``limit`` defaults to the SPEC-V3 bound N = 128."""
    if limit is None:
        limit = VIEW_LIMIT
    raw = text, tuple((i, i + 1) for i in range(len(text)))
    queue, seen, found = [(raw, 0)], {raw}, []
    for view, depth in queue:
        at_bound = False
        for kind in range(3):
            decoded = decode_view(view, kind)
            if decoded in seen:
                continue
            if depth == 8 or len(seen) == limit:
                at_bound = True
                continue
            seen.add(decoded)
            queue.append((decoded, depth + 1))
        if at_bound:
            view_text, spans = view
            for match in COMPONENT.finditer(view_text):
                if any(c in "%\\&" for c in match.group()):
                    found.append((spans[match.start()][0], spans[match.end() - 1][1]))
    return merge(found)


def forms(value):
    result = secret_forms(value)
    for base in (value, value.strip()):
        if not base.strip():
            continue
        result.add(base.encode("utf-8", "surrogatepass").decode("latin-1"))
        units = base.encode("utf-16-le", "surrogatepass")
        result.add(
            "".join(
                chr(int.from_bytes(units[i : i + 2], "little")) for i in range(0, len(units), 2)
            )
        )
    return result


def reference_spans(source, secrets):
    found = []
    for text, spans in views(source):
        for secret in secrets:
            if not secret.strip():
                continue
            for form in forms(secret):
                pos = 0
                while (i := text.find(form, pos)) >= 0:
                    j = i + len(form)
                    a, b = spans[i][0], spans[j - 1][1]
                    left = (
                        len(secret.strip()) >= 12
                        or i == 0
                        or text[i - 1] not in WORD
                        or spans[i - 1][1] - spans[i - 1][0] > 1
                    )
                    right = len(secret.strip()) >= 12 or b == len(source) or source[b] not in WORD
                    if left and right:
                        found.append((a, b))
                    pos = i + 1
        for run in re.finditer(r"[A-Za-z0-9+/_-]+=*", text):
            if any(fragment in run.group() for fragment in _fragments(tuple(secrets))):
                found.append((spans[run.start()][0], spans[run.end() - 1][1]))
    return merge(found)


def merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = merged[-1][0], max(b, merged[-1][1])
        else:
            merged.append((a, b))
    return merged


def mask(text, spans):
    parts, pos = [], 0
    for a, b in merge(spans):
        parts.extend((text[pos:a], "***"))
        pos = b
    return "".join(parts) + text[pos:]


def reference_scrub(text, secrets):
    while True:
        out = mask(text, reference_spans(text, secrets))
        if out == text:
            return text
        text = out


# ------------------------------------------------------------------------ G2 regions
#: Characters a token (G1 patterns) or a base64 run and its padding can hold; any other
#: character is a separator, copied unchanged into every view.
LINKED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + "%&#;\\'\"/" + "+_=-"
)


def segments(text):
    """Maximal runs of linked characters holding an introducer, by a plain scan."""
    out, i = [], 0
    while i < len(text):
        if text[i] not in LINKED:
            i += 1
            continue
        j = i
        while j < len(text) and text[j] in LINKED:
            j += 1
        if any(c in "%&\\" for c in text[i:j]):
            out.append((i, j))
        i = j
    return out


def view_ends(text):
    """(first characters, last characters) of every view of ``text``; (None, None) when
    its closure is bounded or a view is empty (unknown: any character)."""
    hit, ordered = closure(text)
    if hit or not all(v[0] for v in ordered):
        return None, None
    return {v[0][0] for v in ordered}, {v[0][-1] for v in ordered}


def joinable(gap, last, first, secrets):
    """Brute force: does a form hold ``gap`` with a character before it that a view of
    the region before can end with, and one after it that a view of the next can start
    with; or, for a whole-token secret (< 12 characters, G3), start with ``gap`` (its
    left boundary is then a character of a view of the region before)."""
    long_forms = {f for s in secrets if len(s.strip()) >= 12 for f in forms(s)}
    every = {f for s in secrets if s.strip() for f in forms(s)}
    for f in every:
        for k in range(1, len(f) - len(gap)):
            if (
                f[k : k + len(gap)] == gap
                and (last is None or f[k - 1] in last)
                and (first is None or f[k + len(gap)] in first)
            ):
                return True
        if f in long_forms or not (last is None or any(c in WORD for c in last)):
            continue
        m = min(len(f), len(gap))
        if f[:m] == gap[:m] and (len(f) <= len(gap) or first is None or f[len(gap)] in first):
            return True
    return False


def regions(text, secrets):
    """The G2 regions: segments, two neighbours joined when :func:`joinable`."""
    out, previous = [], None
    for start, end in segments(text):
        if out:
            _, last = view_ends(text[previous[0] : previous[1]])
            first, _ = view_ends(text[start:end])
            if joinable(text[out[-1][1] : start], last, first, secrets):
                out[-1] = (out[-1][0], end)
                previous = (start, end)
                continue
        out.append((start, end))
        previous = (start, end)
    return out


def regional_bound(text, secrets):
    """The regional SPEC-V3-1 predicate: some region's closure hits D or N."""
    return any(closure(text[a:b])[0] for a, b in regions(text, secrets))


def regional_components(text, secrets):
    """G5 for AT2(ii), per region: the escape components of each region's views at its
    bound, in source offsets."""
    spans = []
    for a, b in regions(text, secrets):
        spans.extend((a + s, a + e) for s, e in bound_components(text[a:b]))
    return merge(spans)

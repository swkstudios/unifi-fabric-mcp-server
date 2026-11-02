#!/usr/bin/env python3
"""Check public-documentation HTTP links with retry and redirect reporting.

Known pre-publication exclusions are maintained in scripts/doc_links.toml. The
scheduled report records link and archive state without failing the workflow.

Offline by default: links into the current release tag are checked against the working
tree, and no outbound request is made. External links (and the report's repository
archive state) are requested only with ``--external``, or by default inside a GitHub
Actions run (``GITHUB_ACTIONS=true``), where the documentation workflows call this script;
``--offline`` keeps such a run offline too.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import tomllib
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

from check_doc_provenance import MARKER, ROOT, fields, public_reference_docs, sidecar_entries
from check_markdown import _without_code_spans, anchors, link_targets, prose_lines


def probe(url: str, retries: int = 2) -> dict[str, object]:
    target = url.split("#", 1)[0]
    for attempt in range(retries + 1):
        try:
            with urlopen(
                Request(target, headers={"User-Agent": "documentation-link-check/1.0"}),
                timeout=None,
            ) as response:  # noqa: S310 - documented HTTP URLs
                final = response.geturl()
                return {
                    "url": url,
                    "status": response.status,
                    "ok": True,
                    "moved": final != target,
                    "destination": final,
                }
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            status = error.code if isinstance(error, HTTPError) else 0
            if status == 429 and attempt == retries:
                return {"url": url, "status": status, "ok": True, "moved": False}
            if attempt < retries and (status == 0 or status in {408, 429} or status >= 500):
                time.sleep(attempt + 1)
                continue
            return {"url": url, "status": status, "ok": False, "moved": False}
    raise AssertionError("unreachable")


def project_version(root: Path) -> str | None:
    project = root / "pyproject.toml"
    return (
        tomllib.loads(project.read_text()).get("project", {}).get("version")
        if project.exists()
        else None
    )


def reference_texts(root: Path) -> list[str]:
    """Include the current CHANGELOG section copied into the release body."""
    texts = [path.read_text() for path in public_reference_docs(root)]
    changelog = root / "CHANGELOG.md"
    version = project_version(root)
    if changelog.exists() and version:
        section = re.search(
            rf"(?ms)^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
            changelog.read_text(),
        )
        if section:
            texts.append(section.group(1))
    return texts


def discovery(root: Path) -> tuple[list[str], list[dict[str, str]]]:
    exclusions = []
    blocked = {}
    config = root / "scripts/doc_links.toml"
    if config.exists():
        policy = tomllib.loads(config.read_text())
        exclusions.extend(policy.get("exclude", []))
        blocked.update(
            {entry["url"]: entry["reason"] for entry in policy.get("anonymous_blocked", [])}
        )
    found = set()
    for text in reference_texts(root):
        for _, line in prose_lines(text):
            found.update(t for t in link_targets(line) if t.startswith(("http://", "https://")))
            found.update(
                target.rstrip(".,;!?)")
                for target in re.findall(r'https?://[^\s<>\]"\x60]+', _without_code_spans(line))
            )
        found.update(re.findall(r"(?:citation|source)=(https://[^\s>]+)", text))
    excluded = []
    targets = []
    for url in sorted(found):
        if url in blocked:
            excluded.append({"url": url, "status": "NOT-TESTED", "reason": blocked[url]})
        elif any(re.search(pattern, url) for pattern in exclusions):
            excluded.append(
                {
                    "url": url,
                    "status": "NOT-TESTED",
                    "reason": "Known pre-publication/private source reference policy",
                }
            )
        else:
            targets.append(url)
    return targets, excluded


def urls(root: Path) -> list[str]:
    return discovery(root)[0]


def archive_state(url: str) -> dict[str, object] | None:
    match = re.match(r"https://github.com/([^/]+/[^/#?]+)", url)
    if not match:
        return None
    api = f"https://api.github.com/repos/{match.group(1)}"
    try:
        with urlopen(
            Request(api, headers={"User-Agent": "documentation-reference-report/1.0"}), timeout=None
        ) as response:  # noqa: S310 - fixed GitHub API prefix
            info = json.load(response)
        return {
            "repository": match.group(1),
            "archived": bool(info.get("archived")),
            "moved": info.get("full_name", "").lower() != match.group(1).lower(),
        }
    except (HTTPError, URLError, TimeoutError, OSError):
        return {"repository": match.group(1), "state": "UNVERIFIED"}


def current_release_link(url: str, root: Path, version: str | None) -> dict[str, object] | None:
    """Check unpublished current-tag links against the files the tag will contain."""
    parsed = urlsplit(url)
    prefix = f"/swkstudios/unifi-fabric-mcp-server/blob/v{version}/"
    if (
        not version
        or parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or not parsed.path.startswith(prefix)
    ):
        return None
    relative = unquote(parsed.path.removeprefix(prefix))
    target = (root / relative).resolve()
    result: dict[str, object] = {
        "url": url,
        "status": 404,
        "ok": False,
        "moved": False,
        "source": "working-tree",
    }
    if not target.is_relative_to(root.resolve()) or not target.is_file():
        result["reason"] = "release link target does not exist in the working tree"
        return result
    if parsed.fragment:
        try:
            headings = anchors(target.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            headings = set()
        if unquote(parsed.fragment).lower() not in {heading.lower() for heading in headings}:
            result["reason"] = "release link fragment does not match any heading or id"
            return result
    return {**result, "status": 200, "ok": True}


def check(
    root: Path = ROOT, retries: int = 2, *, external: bool = False
) -> list[dict[str, object]]:
    """Discover documentation references, then check precisely those URLs.

    Current-release links are checked against the working tree. Other links are probed
    over HTTP only when ``external`` is true; offline they are left out of the results.
    """
    targets = urls(root)
    version = project_version(root)

    def check_target(url: str) -> dict[str, object] | None:
        local = current_release_link(url, root, version)
        if local is not None:
            return local
        return probe(url, retries=retries) if external else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        return [result for result in pool.map(check_target, targets) if result is not None]


def external_by_default(environ: dict[str, str] | os._Environ[str] = os.environ) -> bool:
    """External links are requested by default only inside a GitHub Actions run."""
    return environ.get("GITHUB_ACTIONS", "").strip().lower() == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="nonblocking moved/archived reference report")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--external",
        action="store_true",
        help="request external links over HTTP (the default only inside GitHub Actions)",
    )
    mode.add_argument(
        "--offline", action="store_true", help="make no outbound request, even in GitHub Actions"
    )
    args = parser.parse_args(argv)
    external = args.external or (not args.offline and external_by_default())
    targets, excluded = discovery(ROOT)
    results = check(ROOT, external=external)
    if args.report:
        repositories = sorted(
            {
                u.split("/blob/", 1)[0].split("/tree/", 1)[0]
                for u in targets
                if u.startswith("https://github.com/")
            }
        )
        states = [state for u in repositories if (state := archive_state(u))] if external else []
        pins = [
            {"document": str(path.relative_to(ROOT)), **fields(marker.group(1))}
            for path in public_reference_docs(ROOT)
            for marker in MARKER.finditer(path.read_text())
        ]
        pins.extend({"document": entry["file"], **entry} for entry in sidecar_entries(ROOT))
        args.report.write_text(
            json.dumps(
                {
                    "source_pins": pins,
                    "links": results,
                    "repositories": states,
                    "excluded": excluded,
                },
                indent=2,
            )
        )
        print(f"nonblocking reference report: {args.report}")
        return 0
    for exception in excluded:
        if "Authenticated client UI" in exception["reason"]:
            print(f"NOT-TESTED: {exception['url']}: {exception['reason']}")
    failed = [r for r in results if not r["ok"]]
    for result in failed:
        print(f"broken external link: {result['url']} (status {result['status']})")
    print(f"external links: {len(results)} checked, {len(failed)} failed")
    if not external:
        print(
            f"offline: {len(targets) - len(results)} external links not requested; "
            "pass --external to check them"
        )
    return bool(failed)


if __name__ == "__main__":
    sys.exit(main())

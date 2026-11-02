## What changed

<!-- What does this PR change, and why? Link the issue it addresses (public issue numbers only). -->

## How it was verified

<!-- The tests you added or ran, and anything you checked by hand. A change to a tool needs a happy-path and an error-path test; a change to host or site resolution needs a multi-key test. -->

## CHANGELOG

- [ ] I added one `changelog.d` fragment (`.added.md`, `.changed.md`, `.fixed.md`, or `.security.md`; see `changelog.d/README.md`) and did not edit `CHANGELOG.md`, or this PR changes no user-visible behavior (add the `skip-changelog` label).
- [ ] I regenerated `docs/TOOLS.md` (`python3 scripts/gen_tools_doc.py`) if I added, removed or renamed a tool or parameter.

## Checklist

- [ ] `ruff check src/ tests/` and `ruff format --check src/ tests/` pass.
- [ ] Test data is synthetic: no real MAC or IP addresses, API keys or hostnames.
- [ ] This PR does not add filtering or redaction to tool responses (see the design invariant in `CONTRIBUTING.md`).

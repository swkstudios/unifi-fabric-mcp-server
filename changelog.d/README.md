# Changelog fragments

Feature lanes add one small Markdown fragment here and do not edit `CHANGELOG.md`.
When preparing a release, the maintainers append each fragment's bullets to its
category in the current release section and delete the fragment.

Use a unique, sortable filename ending in one of these category suffixes:

- `<lane>-<ticket>.added.md`
- `<lane>-<ticket>.changed.md`
- `<lane>-<ticket>.removed.md`
- `<lane>-<ticket>.fixed.md`
- `<lane>-<ticket>.security.md`

`<lane>` and `<ticket>` are lower-case words or numbers joined by hyphens. Any other file in
this directory (no suffix, a misspelt suffix, another extension or a name that is not
lower-case kebab words) would never be folded, so regeneration, `--check` and the CI fragment
lint refuse it. Only `README.md`, `TEMPLATE.md` and `examples/` are exempt.

## Entry style

A reader scans the release notes in a minute. Each entry says what changed and links to where
the detail lives; it never explains.

- **One bullet, one sentence.** At most 25 words, not counting links, starting with a bold area
  label: `**Audit:** ...`. Name at most three tools, settings or parameters; more than that is a
  list, so put it in the documentation and link it.
- **A Details link.** End the bullet with `[Details](<link>)` to a heading anchor in
  `docs/CONFIGURATION.md`, `docs/TOOL-USAGE.md` or another docs page, pinned to the release tag
  (`https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v<X.Y.Z>/docs/<PAGE>.md#<anchor>`).
  The anchor must exist in the docs of the same change: the detail the short bullet drops goes
  there, in the same pull request. A breaking entry links its migration guide instead.
- **An `area:` field.** An indented line after the bullet, `  area: Credentials and audit`,
  names the `####` group the entry is filed under within its category. Reuse an existing area
  where one fits. Removed entries are not grouped and need none.
- **An optional `highlight:` field.** An indented line, `  highlight: <one line>`, offers the
  entry for the release's Highlights list: at most 15 words, no link, no setting or tool name.
  The list holds at most six lines for the whole release, so add one only for a change a user
  would pick this release for.
- **What stays out.** Internal names, CI, test and release tooling, contributor-only changes,
  fixes to code the last public release did not have, route paths, implementation mechanics and
  credits. A change that only contributors see needs no fragment.

The `area:` and `highlight:` lines are read when the fragment is folded and never published:
the entry is filed under its `#### <area>` heading, and a highlight becomes a bullet of the
Highlights list at the top of the release section. Tool counts are
never written by hand: the release section's `Highlights: N tools (A added, R removed)` line
and the Breaking paragraph's counts are generated.

Each fragment contains one or more release-note bullets, beginning with `- `. Keep every
user-facing change represented. For tool additions, use one short line per module that
names each new tool, with no tool count. Example:

```markdown
- **Protect:** live views `create_liveview` and `update_liveview`.
  area: Protect
```

Every other added tool is counted in the release section's family line for its
`docs/TOOLS.md` category heading: "New tools in the catalog's <category> category not named
elsewhere in this section (N tools)", with a tool-list link to that heading. The changelog tests
recompute each count from the registered tools and fail until it is exact; a fragment that
names its tools leaves those counts unchanged.

Do not include internal governance references, rule IDs, reviewer or agent names, or
internal system names; the public-language lint rejects text it matches. Do not add a heading, a release-version heading or an HTML comment:
the release section is published verbatim. After folding, the section is the only copy of
the entry; edit it there.

`TEMPLATE.md` shows the shape of every entry, and `examples/` holds complete, valid
fragments; neither is folded. CI lints every pending fragment before it can be folded: the
file name, the `affected:` tool names (each must be in the catalog, or for a Removed entry
no longer in it), the pinned migration link of every breaking Changed and every Removed
entry, the entry style above, and references that would not work in the public repository (a
bare `#N`, a private issue, pull request or repository, a closing keyword, or a file the
public tree does not ship). The style rules are reported as warnings on a fragment for now and
are errors on the folded release section.

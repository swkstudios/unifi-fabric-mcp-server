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

Each fragment contains one or more release-note bullets, beginning with `- `. Keep every
user-facing change represented. For tool additions, use one short line per module that
names each new tool, with no tool count. Example:

```markdown
- Protect live views: `create_liveview`, `update_liveview`.
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

`TEMPLATE.md` shows the shape of every entry, and `examples/` holds a complete, valid
fragment; neither is folded. CI lints every pending fragment before it can be folded: the
file name, the `affected:` tool names (each must be in the catalog, or for a Removed entry
no longer in it), the pinned migration link of every breaking Changed and every Removed
entry, and references that would not work in the public repository (a bare `#N`, a private
issue, pull request or repository, a closing keyword, or a file the public tree does not
ship).

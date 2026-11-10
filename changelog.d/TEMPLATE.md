# Changelog fragment template

Copy this shape into a new file named `<lane>-<ticket>.<category>.md`: lower-case words
joined by hyphens, then one category suffix. The category picks the release-section
heading the entry lands under:

| Suffix | Heading |
| --- | --- |
| `.added.md` | `### Added` |
| `.changed.md` | `### Changed` |
| `.removed.md` | `### Removed` |
| `.fixed.md` | `### Fixed` |
| `.security.md` | `### Security` |

Fragments of a release are folded in that heading order, and within one heading in file
name order; inside a heading the entries are filed under their `#### <area>` group. Released
sections are never edited by a fold.

The file holds only release-note bullets, each starting with `- `, and the two optional
indented field lines under a bullet. No heading, no HTML comment, no release-version heading.
A non-breaking entry is one sentence of at most 25 words, a bold area label first, then a
link to the documentation that carries the detail:

```markdown
- **<Area>:** <what changed, in one sentence a stranger understands>. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v<X.Y.Z>/docs/<PAGE>.md#<anchor>)
  area: <the #### group this entry is listed under>
  highlight: <optional, at most 15 words, no link and no name; at most six per release>
```

A breaking Changed entry starts with `**Breaking:**` and every Removed entry names the removed
tool. Both carry an `affected:` clause with each affected tool in backticks (a Removed
entry lists tools that are no longer in the catalog; any other entry lists tools that
are), and end with a migration link pinned to the release tag that ships the change:

```markdown
- **Breaking:** <what changed>; affected: `<tool_name>`, `<other_tool>`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v<X.Y.Z>/docs/MIGRATING-<X.Y>.md#<anchor>)
  area: <group>
```

A Removed entry keeps one shape, with a short reason and either the replacement or the words
`No replacement`:

```markdown
- **Breaking (tool removed): `<tool_name>`.** <reason in a few words>. Use `<other_tool>`; affected: `<tool_name>`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v<X.Y.Z>/docs/MIGRATING-<X.Y>.md#<anchor>)
```

The anchor is a heading in that migration guide. For complete, valid fragments see
[examples/example-1.changed.md](examples/example-1.changed.md) and
[examples/example-2.added.md](examples/example-2.added.md).

References must work in the public repository: link a public issue as
`[#N](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/N)`, never a bare
`#N`, a private issue or pull request, another private repository, or a file that the
public tree does not ship. Do not add closing keywords; the release adds the one
closing line.

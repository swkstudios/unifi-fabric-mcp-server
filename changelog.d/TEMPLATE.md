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
name order. Released sections are never edited by a fold.

The file holds only release-note bullets, each starting with `- `. No heading, no HTML
comment, no release-version heading. A non-breaking entry is one plain sentence:

```markdown
- `<tool_name>` <what changed, in one sentence a stranger understands>.
```

A breaking Changed entry starts with `Breaking:` and every Removed entry names the removed
tool. Both carry an `affected:` clause with each affected tool in backticks (a Removed
entry lists tools that are no longer in the catalog; any other entry lists tools that
are), and end with a migration link pinned to the release tag that ships the change:

```markdown
- Breaking: <what changed>; affected: `<tool_name>`, `<other_tool>`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v<X.Y.Z>/docs/MIGRATING-<X.Y>.md#<anchor>).
```

The anchor is a heading in that migration guide. For a complete, valid fragment see
[examples/example-1.changed.md](examples/example-1.changed.md).

References must work in the public repository: link a public issue as
`[#N](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/N)`, never a bare
`#N`, a private issue or pull request, another private repository, or a file that the
public tree does not ship. Do not add closing keywords; the release adds the one
closing line.

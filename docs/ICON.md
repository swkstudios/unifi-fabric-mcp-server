# Icon

The files live in [`docs/assets/icon/`](assets/icon/).

The UniFi Fabric MCP Server icon: a dot-matrix globe of the Americas with one aqua network link.
It is full-bleed on a transparent background at every size. There are two variants: **light**
(`T-light-*`, a black globe, for light pages) and **dark** (`T-dark-*`, a blue globe, for dark
pages). Pair each file with its theme; where a host gives no theme, use the dark variant, which
holds 3:1 contrast on both light and dark backgrounds.

| Files | Use |
|---|---|
| `T-<variant>-1024.png`, `T-<variant>-512.png` | README hero (`<picture>`, 1x and 2x), the registry listing, the Claude Code plugin, the Claude Desktop bundle |
| `T-<variant>-256.png` | any 256 px slot, such as a package-manager README |
| `T-<variant>-128.png/.svg`, `-64`, `-48`, `-32`, `-16` | connector and list icons, drawn on their own pixel grid: pick the nearest size, never rescale |
| `T-<variant>-small.svg` | the 32 px glyph as one small SVG |
| `T-<variant>.svg` | a flat-colour vector twin of the 512 px render |
| `favicon.ico` | 16, 32 and 48 px of the dark variant |

Copies sit where a host needs the file inside its own folder, and a test keeps each one
byte-identical to its source here:

| Host | Files | Source |
|---|---|---|
| Claude Desktop bundle (`plugins/claude-desktop/`) | `icon-{16,32,64,128,256}.png`, `icon-light-{16,32,64,128,256}.png`, `icon.png`, `icon-light.png` | the native 16, 32, 64 and 128 px glyphs and the 256 and 512 px renders, one entry per size and theme in the manifest's `icons` |
| Claude Code plugin (`plugins/claude/.claude-plugin/icon.png`) | one file | the dark 512 px render, declared in `plugin.json` as `icon` (the directory reads that field): the plugin directory takes a square PNG of 512-2048 px, and Claude Code itself does not draw the file |
| Codex plugin (`plugins/codex/assets/`) | `composer-icon.png`, `logo.png` | the native dark 32 px glyph and the dark 512 px render |

Native sizes (128 px and below) are drawn on their own pixel grid: a host that shows the icon
small must be given one of those files, never a downscaled render.

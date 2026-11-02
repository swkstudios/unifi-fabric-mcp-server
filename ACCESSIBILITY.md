# Accessibility

UniFi Fabric MCP Server has no graphical user interface, no web pages and no terminal screens of its own. It is a Model Context Protocol (MCP) server that an AI client starts and talks to over stdio, or over HTTP when you run it in Docker. How accessible a session is depends mostly on the client you choose.

## What the server provides

- Tool results are structured JSON or plain text, and errors are text messages that name the valid choices.
- Nothing depends on color, sound, timing or pointer input.
- The server never asks for input interactively. Configuration is set through environment variables.
- Documentation is plain Markdown, which works with screen readers and text-only browsers.

## Supported clients

Claude Code, Claude Desktop, OpenAI Codex, Google Antigravity, Gemini CLI, ChatGPT (self-hosted HTTPS with OAuth), and any other MCP client. See [Choose your client](README.md#choose-your-client). Each client has its own accessibility features and limits, which this project does not control. Check that client's documentation.

## Known limitations

- Some Protect tools return images, such as `get_camera_snapshot` and `get_thumbnail`. The server does not add text descriptions of image content, so a client or user who cannot view images needs another way to inspect them.
- Some results are long JSON documents. Ask your AI client to summarize or filter them.
- The README demo animation is a screen recording without audio or captions. The same kinds of requests appear as text under Example prompts.

## Report an accessibility barrier

Open a public [GitHub issue](https://github.com/swkstudios/unifi-fabric-mcp-server/issues) and describe the barrier, the client and assistive technology you use, and what you expected. Do not include API keys or private network details. Report security problems as described in [SECURITY.md](.github/SECURITY.md), not in a public issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for how reports and changes are handled.

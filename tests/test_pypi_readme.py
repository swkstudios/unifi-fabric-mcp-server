"""scripts/pypi_readme.py: the PyPI long description has no relative link or image."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("pypi_readme", ROOT / "scripts" / "pypi_readme.py")
assert _SPEC and _SPEC.loader
pypi_readme = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pypi_readme)

REPO = "https://github.com/example/project"


def test_relative_links_and_images_become_absolute_on_main():
    text = (
        "![Banner](docs/banner.png)\n"
        'See [`docs/TOOLS.md`](docs/TOOLS.md) and [policy](.github/SECURITY.md "t").\n'
        "[![CI](https://ci.example/badge.svg)](https://ci.example/run)\n"
        "[up](#configuration) [mail](mailto:a@example.com) [x](./LICENSE)\n"
    )
    out = pypi_readme.absolutize(text, REPO)
    assert (
        "![Banner](https://raw.githubusercontent.com/example/project/main/docs/banner.png)" in out
    )
    assert f"[`docs/TOOLS.md`]({REPO}/blob/main/docs/TOOLS.md)" in out
    assert f'[policy]({REPO}/blob/main/.github/SECURITY.md "t")' in out
    assert "[![CI](https://ci.example/badge.svg)](https://ci.example/run)" in out
    assert "[up](#configuration)" in out and "[mail](mailto:a@example.com)" in out
    assert f"[x]({REPO}/blob/main/LICENSE)" in out
    assert pypi_readme.relative_targets(out) == []
    assert pypi_readme.relative_targets(text) == [
        "docs/banner.png",
        "docs/TOOLS.md",
        ".github/SECURITY.md",
        "./LICENSE",
    ]


def test_the_readme_has_no_relative_target_after_the_rewrite():
    readme = (ROOT / "README.md").read_text()
    assert pypi_readme.relative_targets(readme), "README has no relative link to rewrite"
    out = pypi_readme.absolutize(readme, pypi_readme.repository_url())
    assert pypi_readme.relative_targets(out) == []
    assert out.startswith("<!-- mcp-name: io.github.swkstudios/unifi-fabric-mcp-server -->")
    # The rewrite covers Markdown targets and HTML images (src, srcset); an HTML href is not
    # rewritten, so every one must already be absolute or an in-page anchor.
    html = re.findall(r'\bhref="([^"]*)"', out)
    assert html, "README has no HTML link"
    assert [t for t in html if pypi_readme.is_relative(t)] == []
    assert pypi_readme.relative_targets(out) == []


RAW = "https://raw.githubusercontent.com/example/project/main/"


def test_the_html_hero_images_are_made_absolute():
    text = (
        '<picture><source media="(prefers-color-scheme: dark)" '
        'srcset="docs/a-dark.png 1x, ./docs/a-dark-2.png 2x">'
        '<img src="docs/a.png" srcset="docs/a.png 1x, https://x.example/b.png 2x"></picture>\n'
    )
    assert pypi_readme.relative_targets(text) == [
        "docs/a-dark.png",
        "./docs/a-dark-2.png",
        "docs/a.png",
        "docs/a.png",
    ]
    out = pypi_readme.absolutize(text, REPO)
    assert f'srcset="{RAW}docs/a-dark.png 1x, {RAW}docs/a-dark-2.png 2x"' in out
    assert (
        f'<img src="{RAW}docs/a.png" srcset="{RAW}docs/a.png 1x, https://x.example/b.png 2x">'
        in out
    )
    assert pypi_readme.relative_targets(out) == []


def test_single_quoted_unquoted_and_upper_case_attributes_are_rewritten():
    text = (
        "<img src='docs/one.png' alt='x'>\n"
        "<img src=docs/two.png alt=x>\n"
        '<IMG SRC="docs/three.png" Alt="x">\n'
        "<SOURCE SRCSET='docs/four.png 1x, docs/five.png 2x'>\n"
        "<Source SrcSet=docs/six.png>\n"
        '<img\n  src = "docs/seven.png"\n  width="9"\n/>\n'
    )
    assert len(pypi_readme.relative_targets(text)) == 7
    out = pypi_readme.absolutize(text, REPO)
    assert f"<img src='{RAW}docs/one.png' alt='x'>" in out
    assert f"<img src={RAW}docs/two.png alt=x>" in out
    assert f'<IMG SRC="{RAW}docs/three.png" Alt="x">' in out
    assert f"<SOURCE SRCSET='{RAW}docs/four.png 1x, {RAW}docs/five.png 2x'>" in out
    assert f"<Source SrcSet={RAW}docs/six.png>" in out
    assert f'src = "{RAW}docs/seven.png"' in out
    assert pypi_readme.relative_targets(out) == []


def test_only_img_and_source_src_and_srcset_are_rewritten():
    text = (
        '<img data-src="docs/lazy.png" src="docs/real.png">\n'
        '<script src="docs/app.js"></script>\n'
        '<iframe src="docs/frame.html"></iframe>\n'
        '<video src="docs/clip.mp4"></video>\n'
        '<img alt="the src=docs/in-alt.png attribute" src="docs/alt.png">\n'
        '<a href="docs/page.md">link</a> and prose with src="docs/prose.png" in it\n'
    )
    out = pypi_readme.absolutize(text, REPO)
    assert 'data-src="docs/lazy.png" src="' + RAW + 'docs/real.png"' in out
    assert '<script src="docs/app.js">' in out and '<iframe src="docs/frame.html">' in out
    assert '<video src="docs/clip.mp4">' in out
    assert 'alt="the src=docs/in-alt.png attribute" src="' + RAW + 'docs/alt.png"' in out
    assert '<a href="docs/page.md">' in out and 'prose with src="docs/prose.png" in it' in out
    # and the check does not report what the rewrite leaves alone
    assert pypi_readme.relative_targets(out) == []
    assert pypi_readme.relative_targets(text) == ["docs/real.png", "docs/alt.png"]


def test_code_samples_are_left_alone():
    text = (
        "```html\n"
        '<img src="docs/in-fence.png">\n'
        "![fence](docs/in-fence-md.png)\n"
        "```\n"
        "~~~\n"
        "<img src=docs/in-tilde-fence.png>\n"
        "~~~\n"
        'Inline `<img src="docs/in-inline.png">` and ``<img src=docs/in-double.png>``.\n'
        '<pre><code>&lt;x&gt;<img src="docs/in-pre.png"></code></pre>\n'
        '<code><img src="docs/in-code.png"></code>\n'
        '<img src="docs/outside.png">\n'
        "![md](docs/outside-md.png)\n"
    )
    out = pypi_readme.absolutize(text, REPO)
    for kept in (
        '<img src="docs/in-fence.png">',
        "![fence](docs/in-fence-md.png)",
        "<img src=docs/in-tilde-fence.png>",
        '`<img src="docs/in-inline.png">`',
        "``<img src=docs/in-double.png>``",
        '<img src="docs/in-pre.png">',
        '<img src="docs/in-code.png">',
    ):
        assert kept in out, kept
    assert f'<img src="{RAW}docs/outside.png">' in out
    assert f"![md]({RAW}docs/outside-md.png)" in out
    assert pypi_readme.relative_targets(text) == ["docs/outside-md.png", "docs/outside.png"]
    assert pypi_readme.relative_targets(out) == []


def test_srcset_urls_are_read_the_way_html_reads_them():
    text = (
        '<img srcset="docs/a.png, docs/b.png 2x,docs/c.png 3x" src="docs/a.png">\n'
        '<img srcset="data:image/png;base64,AAAA 1x, docs/d.png 2x">\n'
    )
    out = pypi_readme.absolutize(text, REPO)
    assert f'srcset="{RAW}docs/a.png, {RAW}docs/b.png 2x,{RAW}docs/c.png 3x"' in out
    assert f'srcset="data:image/png;base64,AAAA 1x, {RAW}docs/d.png 2x"' in out
    assert pypi_readme.relative_targets(out) == []


def _check(tmp_path, text: str) -> int:
    path = tmp_path / "README.md"
    path.write_text(text, encoding="utf-8")
    return pypi_readme.main(["--check", str(path)])


def test_check_fails_on_every_relative_image_and_passes_once_rewritten(tmp_path, capsys):
    for relative in (
        '<img src="docs/a.png">',
        "<img src='docs/a.png'>",
        "<img src=docs/a.png>",
        '<IMG SRC="docs/a.png">',
        '<source srcset="docs/a.png 1x">',
        "![a](docs/a.png)",
    ):
        assert _check(tmp_path, relative + "\n") == 1, relative
        rewritten = pypi_readme.absolutize(relative + "\n", REPO)
        assert _check(tmp_path, rewritten) == 0, rewritten
    capsys.readouterr()


def test_check_fails_on_an_image_tag_it_cannot_read(tmp_path, capsys):
    # A tag with no closing ">" and one whose attributes do not parse are not rewritten, so the
    # check must refuse them rather than let a relative image through.
    assert _check(tmp_path, '<img src="docs/a.png"\n<p>text</p>\n') == 1
    assert "docs/a.png" in capsys.readouterr().out
    assert _check(tmp_path, '<img "docs/a.png" src=\'docs/b.png\n') == 1
    assert "unterminated" in capsys.readouterr().out


def test_check_ignores_relative_images_that_are_only_samples(tmp_path):
    assert _check(tmp_path, '```\n<img src="docs/a.png">\n```\nand `<img src=docs/b.png>`\n') == 0


def test_an_empty_src_is_left_untouched_and_is_not_a_target(tmp_path):
    text = (
        '<img src="" alt="x">\n'
        "<img src=''>\n"
        '<source srcset="">\n'
        '<img src="docs/a.png" srcset="">\n'
    )
    out = pypi_readme.absolutize(text, REPO)
    assert '<img src="" alt="x">' in out and "<img src=''>" in out
    assert '<source srcset="">' in out
    assert f'<img src="{RAW}docs/a.png" srcset="">' in out
    assert f'"{RAW}"' not in out and f"'{RAW}'" not in out  # no bare base URL
    assert pypi_readme.relative_targets('<img src="">\n<source srcset="">\n') == []
    assert _check(tmp_path, '<img src="" alt="x">\n') == 0

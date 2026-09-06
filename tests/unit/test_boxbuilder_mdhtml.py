"""Unit tests for boxbuilder.mdhtml -- the build-time Markdown -> themed HTML
renderer behind theme.readme (Desktop README.html, sibling of the Scoring Report).
"""
from boxbuilder import mdhtml


def test_headings_paragraphs_and_inline_markup():
    html = mdhtml.markdown_to_html(
        "# Title\n\n"
        "Intro with **bold**, `code`, and [a link](https://example.com/x).\n\n"
        "## Section\n\nBody text.\n"
    )
    assert "<h1>Title</h1>" in html
    assert "<h2>Section</h2>" in html
    assert "<p>Intro with <strong>bold</strong>, <code>code</code>, "
    'and <a href="https://example.com/x">a link</a>.</p>' in html
    assert "<p>Body text.</p>" in html


def test_lists_and_fenced_code():
    html = mdhtml.markdown_to_html(
        "- one\n- two\n\n1. first\n2. second\n\n```text\nsudo -l\na < b\n```\n"
    )
    assert "<ul>\n<li>one</li>\n<li>two</li>\n</ul>" in html
    assert "<ol>\n<li>first</li>\n<li>second</li>\n</ol>" in html
    assert "<pre><code>sudo -l\na &lt; b</code></pre>" in html


def test_hr_and_soft_wrapped_paragraphs():
    html = mdhtml.markdown_to_html("before\n\n---\n\nafter this line\nwraps into one\n")
    assert "<hr>" in html
    assert "<p>after this line wraps into one</p>" in html


def test_all_text_is_escaped_before_markup():
    html = mdhtml.markdown_to_html("plain <script>alert(1)</script> & stuff")
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert " &amp; stuff" in html


def test_markup_inside_code_span_is_left_alone():
    html = mdhtml.markdown_to_html("run `sudo **id**` now")
    assert "<code>sudo **id**</code>" in html


def test_unterminated_fence_flushes():
    html = mdhtml.markdown_to_html("```\ncode only")
    assert "<pre><code>code only</code></pre>" in html


def test_render_readme_page_branding_and_escaping():
    page = mdhtml.render_readme_page(
        "# hi\n", theme={"title": "Op X", "organization": "DawgSec",
                         "accent": "#c8102e"},
        logo_b64="QUJD",
    )
    assert page.startswith("<!doctype html>")
    assert "<h1>Op X</h1>" in page
    assert '<p class="org">DawgSec</p>' in page
    assert "--accent: #c8102e;" in page
    assert 'src="data:image/png;base64,QUJD"' in page


def test_render_readme_page_defaults_and_bad_accent():
    page = mdhtml.render_readme_page("body", theme={"accent": "not-a-color"})
    assert "<h1>README</h1>" in page
    assert ":root { --accent:" not in page
    assert "<p>body</p>" in page

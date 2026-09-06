"""Markdown -> standalone themed HTML page for the box README.

Authored scenarios keep `theme.readme` as a plain Markdown file; boxbuilder runs
this at build time and uploads the rendered page as the `theme-readme` attachment,
so the Desktop gets a `README.html` that looks like a sibling of the agent's
Scoring Report (same dark palette/masthead as agent/reporter.py) instead of a raw
Markdown file. Build-machine only -- the on-box agent stays pure-consumer and
never renders anything.

`markdown_to_html` intentionally supports only the small Markdown subset the
READMEs actually use: #/##/### headings, paragraphs, `-`/`*` bullets, `1.`
ordered lists, fenced ``` code blocks, `---` rules, and inline `**bold**`,
`` `code` ``, `[text](url)`. Everything is HTML-escaped *before* markup is
applied, so author text can never inject raw HTML.
"""
import html
import re

# Same defensive accent validation as agent/reporter.py (CSS interpolation context).
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_HR_RE = re.compile(r"^-{3,}$|^\*{3,}$")
_UL_RE = re.compile(r"^[-*]\s+(.*)$")
_OL_RE = re.compile(r"^\d+[.)]\s+(.*)$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def _inline(text: str) -> str:
    # Escape first, then layer markup on the escaped text. Code spans are stashed
    # behind placeholders so bold/link markup never touches their contents.
    esc = html.escape(text)
    codes = []

    def _stash(m):
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    def _unstash(m):
        return f"<code>{codes[int(m.group(1))]}</code>"

    esc = _CODE_RE.sub(_stash, esc)
    esc = _BOLD_RE.sub(r"<strong>\1</strong>", esc)
    esc = _LINK_RE.sub(r'<a href="\2">\1</a>', esc)
    return re.sub("\x00(\\d+)\x00", _unstash, esc)


def markdown_to_html(md_text: str) -> str:
    out = []
    para = []
    list_tag = None
    code_buf = None

    def close_para():
        nonlocal para
        if para:
            out.append(f"<p>{_inline(' '.join(para))}</p>")
            para = []

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = None

    for raw in md_text.replace("\r\n", "\n").split("\n"):
        if code_buf is not None:
            if raw.strip().startswith("```"):
                out.append(
                    "<pre><code>"
                    + html.escape("\n".join(code_buf))
                    + "</code></pre>"
                )
                code_buf = None
            else:
                code_buf.append(raw)
            continue

        stripped = raw.strip()
        if stripped.startswith("```"):
            close_para()
            close_list()
            code_buf = []
            continue
        if not stripped:
            close_para()
            close_list()
            continue
        m = _HEADING_RE.match(stripped)
        if m:
            close_para()
            close_list()
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            continue
        if _HR_RE.match(stripped):
            close_para()
            close_list()
            out.append("<hr>")
            continue
        m = _UL_RE.match(stripped)
        if m:
            close_para()
            if list_tag != "ul":
                close_list()
                out.append("<ul>")
                list_tag = "ul"
            out.append(f"<li>{_inline(m.group(1))}</li>")
            continue
        m = _OL_RE.match(stripped)
        if m:
            close_para()
            if list_tag != "ol":
                close_list()
                out.append("<ol>")
                list_tag = "ol"
            out.append(f"<li>{_inline(m.group(1))}</li>")
            continue
        close_list()
        para.append(stripped)

    if code_buf is not None:  # unterminated fence -- flush what we have
        out.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
    close_para()
    close_list()
    return "\n".join(out)


# Mirrors agent/reporter.py's look (same palette variables, masthead, card) so the
# README page and the Scoring Report read as siblings of the same box.
_STYLE = """
:root { --card-bg: #111418; --card-border: #23282e; --muted: #9aa0a6; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
       margin: 0; background: #0b0d10; color: #e6e6e6; line-height: 1.55; }
.container { max-width: 860px; margin: 0 auto; padding: 1.25rem 1.5rem 2rem; }
.masthead { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.25rem; }
.logo { height: 2.2rem; width: auto; border-radius: 4px; }
h1 { margin: 0; font-size: 1.6rem; letter-spacing: -0.01em;
     border-bottom: 3px solid var(--accent, #2a2f36); padding-bottom: 0.2rem;
     display: inline-block; line-height: 1.2; }
.org { color: var(--muted); margin: 0.15rem 0 0; font-size: 0.9rem; }
.card { background: var(--card-bg); border: 1px solid var(--card-border);
        border-radius: 10px; padding: 1.25rem 1.5rem; margin-top: 1rem; }
.card h2 { font-size: 1.15rem; color: #e6e6e6; margin: 1.7rem 0 0.6rem;
           border-bottom: 1px solid var(--card-border); padding-bottom: 0.3rem; }
.card h2:first-child { margin-top: 0; }
.card h3 { font-size: 1rem; color: #e6e6e6; margin: 1.4rem 0 0.5rem; }
.card p { margin: 0.6rem 0; }
.card ul, .card ol { margin: 0.6rem 0; padding-left: 1.4rem; }
.card li { margin: 0.3rem 0; }
.card a { color: #8ab4f8; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       font-size: 0.88em; background: #1a1d21; border: 1px solid #2a2f36;
       border-radius: 4px; padding: 0.08rem 0.35rem; }
pre { background: #1a1d21; border: 1px solid #2a2f36; border-radius: 8px;
      padding: 0.9rem 1.1rem; overflow-x: auto; }
pre code { background: none; border: none; padding: 0; font-size: 0.85rem; }
hr { border: none; border-top: 1px solid var(--card-border); margin: 1.5rem 0; }
strong { color: #ffffff; }
"""


def render_readme_page(md_text: str, theme: dict | None = None,
                       logo_b64: str | None = None) -> str:
    """Render Markdown to a self-contained themed HTML page string.

    `theme` is the scenario's theme dict; `title`/`organization`/`accent` brand the
    masthead (accent validated the same way as agent/reporter.py) and `logo_b64` --
    pre-encoded by the caller -- is embedded as a data: URI.
    """
    theme = theme or {}
    title = html.escape(str(theme.get("title") or "README"))
    organization = theme.get("organization")
    org_html = (
        f'<p class="org">{html.escape(str(organization))}</p>' if organization else ""
    )
    logo_html = (
        f'<img class="logo" src="data:image/png;base64,{html.escape(str(logo_b64))}" alt="">'
        if logo_b64 else ""
    )
    accent = theme.get("accent")
    accent_css = (
        f":root {{ --accent: {accent}; }}\n" if accent and _ACCENT_RE.match(accent) else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} &mdash; README</title>
<style>{accent_css}{_STYLE}</style>
</head>
<body>
<div class="container">
<div class="masthead">{logo_html}<h1>{title}</h1></div>
{org_html}
<div class="card">
{markdown_to_html(md_text)}
</div>
</div>
</body>
</html>
"""

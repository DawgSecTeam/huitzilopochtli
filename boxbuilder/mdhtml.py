"""Markdown -> standalone themed HTML page for the box README.

Authored scenarios keep `theme.readme` as a plain Markdown file; boxbuilder runs
this at build time and uploads the rendered page as the `theme-readme` attachment,
so the Desktop gets a `README.html` that shares the score report's visual language
by importing agent/report_page.py (pure stdlib, so safe to import at build time)
instead of mirroring a second CSS copy. Build-machine only -- the on-box agent
stays pure-consumer and never renders anything.

`markdown_to_html` intentionally supports only the small Markdown subset the
READMEs actually use: #/##/### headings, paragraphs, `-`/`*` bullets, `1.`
ordered lists, fenced ``` code blocks, `---` rules, and inline `**bold**`,
`` `code` ``, `[text](url)`. Everything is HTML-escaped *before* markup is
applied, so author text can never inject raw HTML.
"""
import html
import re

from agent.report_page import accent_css, masthead_html, page_shell

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


def render_readme_page(md_text: str, theme: dict | None = None,
                       logo_b64: str | None = None) -> str:
    """Render Markdown to a self-contained themed HTML page string.

    `theme` is the scenario's theme dict; `title`/`organization`/`accent` brand the
    masthead (accent validated by agent.report_page.accent_css) and `logo_b64` --
    pre-encoded by the caller -- is embedded as a data: URI.
    """
    theme = theme or {}
    title = str(theme.get("title") or "README")
    organization = theme.get("organization")
    body = f"""{masthead_html(title, organization, logo_b64)}
<div class="prose">
{markdown_to_html(md_text)}
</div>"""
    return page_shell(f"{title} — README", body, accent=accent_css(theme.get("accent")))

#!/usr/bin/env python3
"""Render LIVEPATCH.md into site/livepatch.html with the Zathras chrome.

Self-contained Markdown subset converter (no third-party deps): headings,
fenced code blocks, inline code, bold/italic, links, ordered/unordered
lists, blockquotes, horizontal rules, GitHub-style tables and paragraphs.
Run from the repo root or from site/:  python3 site/gen_livepatch.py
"""
import html
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "LIVEPATCH.md")
OUT = os.path.join(HERE, "livepatch.html")


def slug(text):
    s = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[\s_]+", "-", s)


def inline(text):
    """Inline markdown -> HTML. Protects code spans from other rules."""
    spans = []

    def stash(m):
        spans.append(m.group(1))
        return "\x00%d\x00" % (len(spans) - 1)

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text, quote=False)
    # links [text](url)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: '<a href="%s">%s</a>' % (html.escape(m.group(2), quote=True), m.group(1)),
        text,
    )
    # bold then italic
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    # restore code spans
    text = re.sub(
        r"\x00(\d+)\x00",
        lambda m: "<code>%s</code>" % html.escape(spans[int(m.group(1))], quote=False),
        text,
    )
    return text


def convert(md):
    lines = md.split("\n")
    out = []
    toc = []
    i = 0
    n = len(lines)

    def close_lists(stack):
        while stack:
            out.append("</%s>" % stack.pop())

    list_stack = []

    while i < n:
        line = lines[i]

        # fenced code block
        m = re.match(r"^```(.*)$", line)
        if m:
            close_lists(list_stack)
            i += 1
            buf = []
            while i < n and not re.match(r"^```\s*$", lines[i]):
                buf.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            code = html.escape("\n".join(buf), quote=False)
            out.append("<pre><code>%s</code></pre>" % code)
            continue

        # horizontal rule
        if re.match(r"^---+\s*$", line):
            close_lists(list_stack)
            out.append("<hr>")
            i += 1
            continue

        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            close_lists(list_stack)
            level = len(m.group(1))
            txt = m.group(2).strip()
            sid = slug(txt)
            if level == 2:
                toc.append((sid, txt))
            out.append('<h%d id="%s">%s</h%d>' % (level, sid, inline(txt), level))
            i += 1
            continue

        # table (header row followed by a |---| separator)
        if "|" in line and i + 1 < n and re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", lines[i + 1]):
            close_lists(list_stack)

            def cells(row):
                row = row.strip()
                if row.startswith("|"):
                    row = row[1:]
                if row.endswith("|"):
                    row = row[:-1]
                return [c.strip() for c in row.split("|")]

            header = cells(line)
            i += 2
            out.append("<table><thead><tr>")
            for c in header:
                out.append("<th>%s</th>" % inline(c))
            out.append("</tr></thead><tbody>")
            while i < n and "|" in lines[i] and lines[i].strip():
                for c in cells(lines[i]):
                    pass
                row = cells(lines[i])
                out.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in row) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue

        # blockquote
        if re.match(r"^>\s?", line):
            close_lists(list_stack)
            buf = []
            while i < n and re.match(r"^>\s?", lines[i]):
                buf.append(re.sub(r"^>\s?", "", lines[i]))
                i += 1
            out.append("<blockquote>%s</blockquote>" % inline(" ".join(buf)))
            continue

        # list item (ordered / unordered), with 1 level of nesting by indent
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if m:
            indent = len(m.group(1))
            ordered = bool(re.match(r"\d+\.", m.group(2)))
            tag = "ol" if ordered else "ul"
            depth = 1 if indent >= 2 else 0
            # adjust stack to desired depth
            while len(list_stack) > depth + 1:
                out.append("</%s>" % list_stack.pop())
            if len(list_stack) == depth + 1 and list_stack[-1] != tag:
                out.append("</%s>" % list_stack.pop())
            while len(list_stack) < depth + 1:
                out.append("<%s>" % tag)
                list_stack.append(tag)
            out.append("<li>%s</li>" % inline(m.group(3)))
            i += 1
            continue

        # blank line
        if not line.strip():
            close_lists(list_stack)
            i += 1
            continue

        # paragraph (gather consecutive non-structural lines)
        close_lists(list_stack)
        buf = [line]
        i += 1
        while i < n and lines[i].strip() and not re.match(
            r"^(#{1,6}\s|```|>|\s*([-*]|\d+\.)\s|---+\s*$)", lines[i]
        ):
            buf.append(lines[i])
            i += 1
        out.append("<p>%s</p>" % inline(" ".join(buf)))

    close_lists(list_stack)
    return "\n".join(out), toc


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Livepatching Guide // Zathras</title>
<meta name="description" content="A practical guide to Linux kernel livepatching and a step-by-step tutorial, part of the Zathras toolkit.">
<link rel="stylesheet" href="assets/matrix.css">
</head>
<body>
<canvas id="matrix-rain"></canvas>

<header class="site">
\t<div class="wrap">
\t\t<a class="brand" href="index.html">Zathras<span class="blink">_</span>
\t\t\t<span class="sub">// LIVEPATCHING GUIDE</span></a>
\t\t<nav class="main">
\t\t\t<a href="index.html">Overview</a>
\t\t\t<a href="modules.html">Modules</a>
\t\t\t<a href="livepatch.html" class="active">Livepatching Guide</a>
\t\t\t<a class="gh" href="https://github.com/hackman/kernel-livepatches" target="_blank" rel="noopener" title="GitHub repository"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>GitHub</a>
\t\t</nav>
\t</div>
</header>

<main>
\t<div class="wrap">
\t\t<div class="toc">
\t\t\t<strong>// contents</strong>
\t\t\t<ol>
{toc}
\t\t\t</ol>
\t\t</div>
\t\t<article class="md">
{body}
\t\t</article>
\t</div>
</main>

<footer class="site">
\t<div class="wrap">
\t\tZathras &mdash; rendered from <code>LIVEPATCH.md</code>. Zathras is here to help.
\t</div>
</footer>

<script src="assets/matrix.js"></script>
</body>
</html>
"""


def main():
    if not os.path.exists(SRC):
        sys.exit("LIVEPATCH.md not found at %s" % SRC)
    with open(SRC, encoding="utf-8") as f:
        md = f.read()
    body, toc = convert(md)
    toc_html = "\n".join(
        '\t\t\t\t<li><a href="#%s">%s</a></li>' % (sid, html.escape(txt, quote=False))
        for sid, txt in toc
    )
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(PAGE.format(toc=toc_html, body=body))
    print("wrote %s (%d sections)" % (OUT, len(toc)))


if __name__ == "__main__":
    main()

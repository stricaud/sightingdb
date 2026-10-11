# The SightingDB book

One markdown file per chapter in `chapters/`, built into a PDF or a
single-file HTML version.

```bash
make            # the PDF
make html       # one self-contained HTML file
make check      # what is installed and what is missing
make clean      # remove the built book, keep the diagram cache
make distclean  # remove everything built
```

## What it needs

| Tool | For | Install |
| --- | --- | --- |
| pandoc | both | `brew install pandoc` |
| xelatex | the PDF | `brew install --cask mactex-no-gui` |
| mermaid-cli | the diagrams | `npm install -g @mermaid-js/mermaid-cli` |
| node | the screenshots | comes with mermaid-cli |

Without mermaid-cli the book still builds, with each diagram shown as its
source rather than missing.

## How it fits together

| | |
| --- | --- |
| `chapters/*.md` | The book. Built in filename order. |
| `metadata.yaml` | Title, author, page size, fonts. |
| `style/book.tex` | The PDF's typography and the logo palette. |
| `style/book.css` | The same, for the HTML. |
| `style/cover.html` | The HTML title block; the PDF builds its own in LaTeX. |
| `style/mermaid.json` | The diagram theme, in the same colours. |
| `tools/mermaid.lua` | Renders ```mermaid blocks at build time. |
| `tools/screenshots.mjs` | Captures the interface from a running server. |
| `images/` | Screenshots and the logo. |
| `build/diagrams/` | Rendered diagrams, cached by content. |

Diagrams are written as fenced ` ```mermaid ` blocks, so they render on GitHub
and in an editor and stay diffable. The filter turns each one into a picture at
build time — PDF for LaTeX, SVG for HTML — and caches it by a hash of its
source, so a rebuild only redraws what changed.

## Re-taking the screenshots

They come from a real server. The galaxy in `doc/docker` is what these were
taken from:

```bash
docker compose -f ../docker/docker-compose.yml up -d
make screenshots
```

It signs in, visits each page and captures it, forcing light mode because a
dark screenshot on a white page looks like a mistake rather than a choice.
`SIGHTINGDB_LB`, `SIGHTINGDB_NODE` and `SIGHTINGDB_KEY` override where it
looks.

## The colours

From the logo — a gold star on a deep night sky — sampled from
`doc/sightingdb-logo3_256.png` rather than chosen by eye:

| | |
| --- | --- |
| `#01024C` | night: headings, rules, the cover |
| `#FDD32A` | star: chapter numbers, accents, bullets |
| `#8F7832` | dim star: gold dark enough to read on paper |
| `#1B1F24` | ink: body text, the same as the interface |

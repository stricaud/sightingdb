#!/usr/bin/env bash
#
# Rebuild the book and stage it for publishing.
#
#     ./update-docs.sh
#
# Builds doc/the-sightingdb-book into HTML and PDF, checks the result is
# actually complete, and copies it into docs/ — which is what GitHub Pages
# serves from (Settings -> Pages -> Deploy from a branch -> master, /docs).
#
# It does not commit and it does not push. Those are yours to run, and the
# script prints them when it is done.
#
# Why the checking: the diagrams are rendered at build time by a browser, and
# when that fails pandoc still produces a perfectly valid book — with the
# mermaid source printed where each picture should be. It looks fine from the
# command line and wrong on the website. That failure has happened, so this
# refuses to stage a book it cannot verify.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
book="$here/doc/the-sightingdb-book"
site="$here/docs"

say()  { printf '  %s\n' "$*"; }
step() { printf '\n%s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# --- what it needs ---------------------------------------------------------

step "Checking the toolchain"
missing=()
for tool in pandoc xelatex mmdc; do
    if command -v "$tool" >/dev/null 2>&1; then
        say "$tool $(command -v "$tool")"
    else
        missing+=("$tool")
        say "$tool MISSING"
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    printf '\n'
    for tool in "${missing[@]}"; do
        case "$tool" in
            pandoc)  say "pandoc:  brew install pandoc" ;;
            xelatex) say "xelatex: brew install --cask mactex-no-gui" ;;
            mmdc)    say "mmdc:    npm install -g @mermaid-js/mermaid-cli" ;;
        esac
    done
    die "install the above and run this again"
fi

# --- build -----------------------------------------------------------------

step "Building"
html="$book/the-sightingdb-book.html"
pdf="$book/the-sightingdb-book.pdf"

# The outputs go first so make cannot decide there is nothing to do. It makes
# that decision on timestamps, and a stale book that is merely *newer* than
# its sources would otherwise sail through the checks below and be published
# as if it were fresh — which is the one thing a script named "update" must
# not do. The diagram cache is left alone: it is keyed by content, so nothing
# is redrawn that has not changed.
rm -f "$html" "$pdf"
make -C "$book" html pdf
[ -s "$html" ] || die "no HTML was produced"
[ -s "$pdf" ]  || die "no PDF was produced"

# --- check it is whole -----------------------------------------------------

step "Checking the book is complete"

# However many diagrams the chapters contain, that many pictures must have
# reached the HTML. Counted from the source rather than hardcoded, so adding a
# diagram does not quietly weaken the check.
# `|| true` on every count, because grep exits 1 when it finds nothing and
# `set -o pipefail` would then kill this script before it could say so —
# silently, and only ever in the one case these checks exist for: a book with
# no diagrams in it.
count() { grep -o "$1" "$2" | wc -l | tr -d ' ' || true; }

want=$(grep -c '^```mermaid' "$book"/chapters/*.md | awk -F: '{n += $2} END {print n+0}')
got=$(count 'data:image/svg+xml' "$html")
say "diagrams: $got of $want rendered"
[ "$got" -eq "$want" ] || die "$((want - got)) diagram(s) did not render. \
Look for 'mermaid:' in the build output above."

# The giveaway when they do not: the diagram's source ends up in the text.
if grep -qE '^(flowchart|sequenceDiagram)' "$html"; then
    die "diagram source is showing in the HTML, so some did not render"
fi

shots=$(count 'data:image/png' "$html")
say "screenshots: $shots embedded"
[ "$shots" -gt 0 ] || die "no screenshots in the HTML; is images/ populated?"

# Self-contained or the site breaks: nothing may point at a local file.
if grep -oE 'src="(?!data:)[^"]+"' "$html" 2>/dev/null | grep -qv 'src="data:'; then
    die "the HTML refers to files outside itself; it must be self-contained"
fi

grep -q 'class="cover"' "$html" || die "the cover is missing from the HTML"
say "self-contained: yes"

pages=$(pdfinfo "$pdf" 2>/dev/null | awk '/^Pages:/ {print $2}')
say "PDF: ${pages:-?} pages, $(du -h "$pdf" | cut -f1)"
say "HTML: $(du -h "$html" | cut -f1)"

# --- stage -----------------------------------------------------------------

step "Copying into docs/"
mkdir -p "$site"
cp "$html" "$site/index.html"
cp "$pdf"  "$site/the-sightingdb-book.pdf"
# Without this, GitHub runs the output through Jekyll, which ignores files and
# directories beginning with an underscore.
touch "$site/.nojekyll"
say "docs/index.html"
say "docs/the-sightingdb-book.pdf"
say "docs/.nojekyll"

# --- what to do next -------------------------------------------------------

step "Done."

if git -C "$here" diff --quiet -- docs 2>/dev/null &&
   git -C "$here" diff --cached --quiet -- docs 2>/dev/null &&
   [ -z "$(git -C "$here" ls-files --others --exclude-standard -- docs)" ]; then
    say "docs/ is unchanged — the published book is already up to date."
    exit 0
fi

cat <<'NEXT'

  To publish:

      git add docs doc/the-sightingdb-book
      git commit -m "Update the book"
      git push

  The site is served from the docs/ folder on master:
  https://stricaud.github.io/sightingdb/
NEXT

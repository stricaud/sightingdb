# The SightingDB book.
#
#   make           the PDF
#   make html      a single-page HTML version
#   make screenshots   capture the interface from a running server
#   make clean     remove the built book, keeping the diagram cache
#   make distclean remove everything built
#
# Needs pandoc and a LaTeX engine for the PDF, and mermaid-cli for the
# diagrams. `make check` says what is missing.

BOOK      := the-sightingdb-book
CHAPTERS  := $(sort $(wildcard chapters/*.md))
# Images are prerequisites too: re-taking a screenshot should rebuild the book,
# which it did not until this line existed.
IMAGES    := $(wildcard images/*)
STYLE     := style/book.tex
META      := metadata.yaml
FILTER    := tools/mermaid.lua
BUILD     := build

PANDOC    ?= pandoc
ENGINE    ?= xelatex

# The diagram cache is keyed by content, so it survives a `make clean` and a
# rebuild only redraws what changed.
export MERMAID_CACHE  := $(BUILD)/diagrams
export MERMAID_CONFIG := style/mermaid.json
export MERMAID_CSS    := style/mermaid.css
# Only set where the browser mermaid-cli drives needs --no-sandbox, which in
# practice means a CI container running as root. The workflow sets it.
export MERMAID_PUPPETEER

PANDOC_FLAGS := \
  --from=markdown+smart+pipe_tables+fenced_code_attributes \
  --metadata-file=$(META) \
  --lua-filter=$(FILTER) \
  --toc \
  --number-sections \
  --syntax-highlighting=tango \
  --resource-path=.:images:$(BUILD)

.PHONY: all pdf html check clean distclean screenshots

all: pdf

pdf: $(BOOK).pdf

$(BOOK).pdf: $(CHAPTERS) $(IMAGES) $(STYLE) $(META) $(FILTER) | $(MERMAID_CACHE)
	@command -v $(PANDOC) >/dev/null || { \
	  echo "pandoc is not installed. brew install pandoc"; exit 1; }
	@command -v $(ENGINE) >/dev/null || { \
	  echo "$(ENGINE) is not installed. brew install --cask mactex-no-gui"; exit 1; }
	@command -v mmdc >/dev/null || \
	  echo "note: mermaid-cli is missing, so diagrams will appear as source."
	$(PANDOC) $(PANDOC_FLAGS) \
	  --pdf-engine=$(ENGINE) \
	  --include-in-header=$(STYLE) \
	  --top-level-division=chapter \
	  -o $@ $(CHAPTERS)
	@echo "wrote $@"

# The same book, as one self-contained HTML file: diagrams as SVG rather than
# PDF, the stylesheet and every image inlined, so it can be mailed or dropped
# on a web server with nothing beside it.
html: $(BOOK).html

$(BOOK).html: $(CHAPTERS) $(IMAGES) $(META) $(FILTER) style/book.css style/cover.html | $(MERMAID_CACHE)
	@command -v $(PANDOC) >/dev/null || { \
	  echo "pandoc is not installed. brew install pandoc"; exit 1; }
	@command -v mmdc >/dev/null || \
	  echo "note: mermaid-cli is missing, so diagrams will appear as source."
	$(PANDOC) $(PANDOC_FLAGS) \
	  --standalone \
	  --embed-resources \
	  --css=style/book.css \
	  --include-before-body=style/cover.html \
	  --section-divs \
	  -o $@ $(CHAPTERS)
	@echo "wrote $@ ($$(du -h $@ | cut -f1))"

$(MERMAID_CACHE):
	@mkdir -p $@

# Capture the management interface from a server you are already running.
# Defaults to the galaxy in doc/docker.
screenshots:
	@node tools/screenshots.mjs

check:
	@for tool in $(PANDOC) $(ENGINE) mmdc node; do \
	  printf '  %-10s %s\n' "$$tool" "$$(command -v $$tool 2>/dev/null || echo 'MISSING')"; \
	done

clean:
	rm -f $(BOOK).pdf $(BOOK).html

distclean: clean
	rm -rf $(BUILD)

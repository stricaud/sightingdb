-- Render ```mermaid blocks into images at build time.
--
-- The chapters keep the diagram *source* in a fenced block, so they render on
-- GitHub and in any editor and stay diffable. This filter turns each one into
-- a picture for the PDF, which LaTeX cannot do on its own.
--
-- Rendered output is cached by a hash of the source and the theme, because
-- mermaid-cli starts a browser for every call: without the cache a rebuild of
-- a twelve-diagram book spends a minute drawing pictures that have not
-- changed.

local cache = os.getenv("MERMAID_CACHE") or "build/diagrams"
local config = os.getenv("MERMAID_CONFIG") or "style/mermaid.json"
local css = os.getenv("MERMAID_CSS") or "style/mermaid.css"
-- mermaid-cli drives a headless browser, which refuses to start as root
-- without `--no-sandbox` — which is exactly what a CI container is. Set
-- MERMAID_PUPPETEER to a file holding {"args": ["--no-sandbox"]} there, and
-- leave it unset everywhere else: passing --no-sandbox on a workstation would
-- be turning off a protection for no reason.
local puppeteer = os.getenv("MERMAID_PUPPETEER")

-- PDF for LaTeX, SVG for everything else. Both are vector, so a diagram is
-- sharp in print and sharp at any zoom in a browser; what differs is only
-- which of them the renderer can actually place on a page.
local function wanted_format()
  if FORMAT and FORMAT:match("latex") then
    return "pdf"
  end
  return "svg"
end

-- djb2: enough to tell two diagrams apart, and no dependency.
local function digest(text)
  local hash = 5381
  for i = 1, #text do
    hash = (hash * 33 + text:byte(i)) % 4294967296
  end
  return string.format("%08x", hash)
end

local function exists(path)
  local handle = io.open(path, "r")
  if handle then handle:close() return true end
  return false
end

local warned = false

function CodeBlock(block)
  if not block.classes:includes("mermaid") then
    return nil
  end

  -- The format is part of the key: the same diagram is cached once per
  -- output, so building the PDF does not throw away the SVG and back again.
  local extension = wanted_format()
  local key = digest(block.text .. (block.attributes["caption"] or "")) .. "-" .. extension
  local source = cache .. "/" .. key .. ".mmd"
  local image = cache .. "/" .. key .. "." .. extension

  if not exists(image) then
    local out = io.open(source, "w")
    if not out then
      io.stderr:write("mermaid: cannot write " .. source .. "\n")
      return nil
    end
    out:write(block.text)
    out:close()

    -- `-b transparent` so the diagram sits on the page rather than in a white
    -- box of its own; the theme comes from the config so every diagram in the
    -- book is drawn in the logo's colours.
    local command = string.format(
      "mmdc --quiet -i %s -o %s -b transparent -c %s -C %s%s 2>&1",
      source, image, config, css,
      puppeteer and (" -p " .. puppeteer) or ""
    )
    local pipe = io.popen(command)
    local output = pipe and pipe:read("*a") or ""
    local ok = pipe and pipe:close()

    -- mermaid-cli writes the drawing onto a full US Letter page and leaves it
    -- in the top-left corner, so a diagram placed at 88% of the text width
    -- comes out small, left-aligned and followed by half a page of nothing.
    -- Trimming to the ink is what makes `width` mean what it says. SVG needs
    -- none of this: it carries a viewBox around the drawing already.
    if ok and extension == "pdf" and exists(image) then
      local trim = io.popen(string.format(
        "pdfcrop --margins 2 %s %s 2>&1", image, image))
      local trimmed = trim and trim:read("*a") or ""
      local cropped = trim and trim:close()
      if not cropped then
        io.stderr:write(
          "mermaid: pdfcrop failed, so diagrams keep their page margins: " ..
          trimmed .. "\n")
      end
    end

    if not ok or not exists(image) then
      if not warned then
        io.stderr:write(
          "\nmermaid: mmdc could not render a diagram, so the source is shown\n" ..
          "         instead. Install it with:  npm install -g @mermaid-js/mermaid-cli\n"
        )
        warned = true
      end
      if output ~= "" then io.stderr:write("         " .. output:gsub("\n", "\n         ")) end
      -- Falling back to the source text rather than dropping it: a book with
      -- a code block where a picture should be is still readable, and a book
      -- with a silent gap is not.
      return pandoc.CodeBlock(block.text)
    end
  end

  local caption = block.attributes["caption"]
  local width = block.attributes["width"] or "88%"
  local height = block.attributes["height"] or "58%"

  if FORMAT:match("latex") then
    -- Written as LaTeX rather than handed to pandoc as an image, for one
    -- option pandoc will not emit: `keepaspectratio`. It adds that only when
    -- a single dimension is given, and both are needed here — a width alone
    -- scales a tall top-to-bottom diagram to the full height of the text
    -- block, where it can share a page with nothing and strands the
    -- paragraph that introduces it on an empty one. With both and without
    -- keepaspectratio, the picture is simply stretched to fit.
    --
    -- Centred and not a float: a diagram belongs where it was written, and a
    -- LaTeX figure would drift.
    local fraction = function(value)
      -- The extra parentheses are load-bearing: gsub returns the string and
      -- a replacement count, and tonumber would take that count as a base.
      return tostring(tonumber((value:gsub("%%", ""))) / 100)
    end
    local latex = string.format(
      "\\begin{center}\n" ..
      "\\includegraphics[width=%s\\linewidth,height=%s\\textheight," ..
      "keepaspectratio]{%s}\n" ..
      "\\end{center}",
      fraction(width), fraction(height), image
    )
    local blocks = { pandoc.RawBlock("latex", latex) }
    if caption then
      table.insert(blocks, pandoc.Para(pandoc.read(caption).blocks[1].content))
    end
    return blocks
  end

  local picture = pandoc.Image(
    caption and pandoc.read(caption).blocks[1].content or {},
    image,
    caption or "",
    pandoc.Attr("", {}, {{"width", width}})
  )
  return pandoc.Para({picture})
end

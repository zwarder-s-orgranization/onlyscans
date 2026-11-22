export type InlineNode =
  | { type: "text"; value: string }
  | { type: "code"; value: string }
  | { type: "strong"; children: InlineNode[] }
  | { type: "em"; children: InlineNode[] }
  | { type: "del"; children: InlineNode[] }
  | { type: "link"; href: string; children: InlineNode[] }
  | { type: "br" };

export interface ListItemNode {
  children: InlineNode[];
  nested: BlockNode[];
  checked?: boolean;
}

export type TableAlign = "left" | "center" | "right" | null;

export type BlockNode =
  | { type: "heading"; level: 1 | 2 | 3 | 4 | 5 | 6; children: InlineNode[] }
  | { type: "paragraph"; children: InlineNode[] }
  | { type: "code"; lang: string; value: string }
  | { type: "blockquote"; children: BlockNode[] }
  | { type: "list"; ordered: boolean; start: number; items: ListItemNode[] }
  | { type: "table"; headers: InlineNode[][]; align: TableAlign[]; rows: InlineNode[][][] }
  | { type: "hr" };

const ESCAPABLE = new Set([
  "\\",
  "`",
  "*",
  "_",
  "{",
  "}",
  "[",
  "]",
  "(",
  ")",
  "#",
  "+",
  "-",
  ".",
  "!",
  "~",
  "|",
  ">",
]);

function isWordChar(ch: string | undefined): boolean {
  if (!ch) return false;
  return /[\p{L}\p{N}_]/u.test(ch);
}

function sanitizeHref(raw: string): string | null {
  const trimmed = raw.trim().replace(/^<(.+)>$/, "$1").trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("#") || trimmed.startsWith("/")) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (
      parsed.protocol === "https:" ||
      parsed.protocol === "http:" ||
      parsed.protocol === "mailto:"
    ) {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

function findCodeSpanEnd(src: string, startAfterTicks: number, tickCount: number): number {
  let i = startAfterTicks;
  while (i < src.length) {
    if (src[i] === "`") {
      let run = 0;
      while (i + run < src.length && src[i + run] === "`") run++;
      if (run === tickCount) {
        return i;
      }
      i += run;
    } else {
      i++;
    }
  }
  return -1;
}

function findClosingDelimiter(
  src: string,
  from: number,
  delim: string,
  requireBoundaryAfter = false,
): number {
  let i = from;
  while (i <= src.length - delim.length) {
    const ch = src[i];
    if (ch === "\\" && i + 1 < src.length) {
      i += 2;
      continue;
    }
    if (ch === "`") {
      let ticks = 0;
      while (i + ticks < src.length && src[i + ticks] === "`") ticks++;
      const close = findCodeSpanEnd(src, i + ticks, ticks);
      if (close !== -1) {
        i = close + ticks;
        continue;
      }
      i += ticks;
      continue;
    }
    if (src.startsWith(delim, i)) {
      const prev = i > from ? src[i - 1] : "";
      const after = src[i + delim.length];
      const notEmpty = i > from;
      const notPrecededBySpace = !/\s/.test(prev);
      const exactSingle =
        delim.length !== 1 || (src[i - 1] !== delim && after !== delim);
      const boundaryOk = !requireBoundaryAfter || !isWordChar(after);
      if (notEmpty && notPrecededBySpace && exactSingle && boundaryOk) {
        return i;
      }
    }
    i++;
  }
  return -1;
}

function parseLinkAt(
  src: string,
  start: number,
): { node: InlineNode; nextPos: number } | null {
  if (src[start] !== "[") return null;
  let depth = 0;
  let i = start;
  let closeBracket = -1;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "\\" && i + 1 < src.length) {
      i += 2;
      continue;
    }
    if (ch === "`") {
      let ticks = 0;
      while (i + ticks < src.length && src[i + ticks] === "`") ticks++;
      const close = findCodeSpanEnd(src, i + ticks, ticks);
      if (close !== -1) {
        i = close + ticks;
        continue;
      }
      i += ticks;
      continue;
    }
    if (ch === "[") {
      depth++;
    } else if (ch === "]") {
      depth--;
      if (depth === 0) {
        closeBracket = i;
        break;
      }
    }
    i++;
  }
  if (closeBracket === -1 || src[closeBracket + 1] !== "(") return null;

  let parenDepth = 0;
  let j = closeBracket + 1;
  let closeParen = -1;
  while (j < src.length) {
    const ch = src[j];
    if (ch === "\\" && j + 1 < src.length) {
      j += 2;
      continue;
    }
    if (ch === "(") {
      parenDepth++;
    } else if (ch === ")") {
      parenDepth--;
      if (parenDepth === 0) {
        closeParen = j;
        break;
      }
    }
    j++;
  }
  if (closeParen === -1) return null;

  const label = src.slice(start + 1, closeBracket);
  const rawDest = src.slice(closeBracket + 2, closeParen).trim();
  const urlPart = rawDest.split(/\s+/)[0] ?? "";
  const href = sanitizeHref(urlPart);
  if (!href) return null;

  return {
    node: {
      type: "link",
      href,
      children: parseMarkdownInline(label),
    },
    nextPos: closeParen + 1,
  };
}

export function parseMarkdownInline(input: string): InlineNode[] {
  const nodes: InlineNode[] = [];
  let textBuf = "";

  const flushText = () => {
    if (textBuf.length > 0) {
      nodes.push({ type: "text", value: textBuf });
      textBuf = "";
    }
  };

  let i = 0;
  while (i < input.length) {
    const ch = input[i];

    // Escaped punctuation or hard line break with trailing backslash
    if (ch === "\\" && i + 1 < input.length) {
      const next = input[i + 1];
      if (next === "\n") {
        flushText();
        nodes.push({ type: "br" });
        i += 2;
        continue;
      }
      if (ESCAPABLE.has(next)) {
        textBuf += next;
        i += 2;
        continue;
      }
    }

    // Hard line break with two trailing spaces
    if (ch === " " && input[i + 1] === " " && input[i + 2] === "\n") {
      flushText();
      nodes.push({ type: "br" });
      i += 3;
      continue;
    }

    // Inline code span
    if (ch === "`") {
      let ticks = 0;
      while (i + ticks < input.length && input[i + ticks] === "`") ticks++;
      const close = findCodeSpanEnd(input, i + ticks, ticks);
      if (close !== -1) {
        let code = input.slice(i + ticks, close);
        if (
          code.length >= 2 &&
          code.startsWith(" ") &&
          code.endsWith(" ") &&
          /[^ ]/.test(code)
        ) {
          code = code.slice(1, -1);
        }
        flushText();
        nodes.push({ type: "code", value: code });
        i = close + ticks;
        continue;
      }
      textBuf += input.slice(i, i + ticks);
      i += ticks;
      continue;
    }

    // Link [text](href)
    if (ch === "[") {
      const parsed = parseLinkAt(input, i);
      if (parsed) {
        flushText();
        nodes.push(parsed.node);
        i = parsed.nextPos;
        continue;
      }
    }

    // Strong (**...** or __...__)
    if (
      (ch === "*" && input[i + 1] === "*") ||
      (ch === "_" && input[i + 1] === "_" && !isWordChar(input[i - 1]))
    ) {
      const delim = ch + ch;
      const next = input[i + 2];
      if (next && !/\s/.test(next)) {
        const close = findClosingDelimiter(input, i + 2, delim, ch === "_");
        if (close !== -1) {
          flushText();
          nodes.push({
            type: "strong",
            children: parseMarkdownInline(input.slice(i + 2, close)),
          });
          i = close + 2;
          continue;
        }
      }
    }

    // Strikethrough (~~...~~)
    if (ch === "~" && input[i + 1] === "~") {
      const next = input[i + 2];
      if (next && !/\s/.test(next)) {
        const close = findClosingDelimiter(input, i + 2, "~~");
        if (close !== -1) {
          flushText();
          nodes.push({
            type: "del",
            children: parseMarkdownInline(input.slice(i + 2, close)),
          });
          i = close + 2;
          continue;
        }
      }
    }

    // Emphasis (*...* or _..._)
    if (
      (ch === "*" && input[i + 1] !== "*") ||
      (ch === "_" && input[i + 1] !== "_" && !isWordChar(input[i - 1]))
    ) {
      const next = input[i + 1];
      if (next && !/\s/.test(next)) {
        const close = findClosingDelimiter(input, i + 1, ch, ch === "_");
        if (close !== -1) {
          flushText();
          nodes.push({
            type: "em",
            children: parseMarkdownInline(input.slice(i + 1, close)),
          });
          i = close + 1;
          continue;
        }
      }
    }

    textBuf += ch;
    i++;
  }

  flushText();
  return nodes;
}

function measureIndent(line: string): number {
  let count = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === " ") {
      count += 1;
    } else if (line[i] === "\t") {
      count += 2;
    } else {
      break;
    }
  }
  return count;
}

function stripIndent(line: string, spaces: number): string {
  let removed = 0;
  let i = 0;
  while (i < line.length && removed < spaces) {
    if (line[i] === " ") {
      removed += 1;
      i++;
    } else if (line[i] === "\t") {
      removed += 2;
      i++;
    } else {
      break;
    }
  }
  return line.slice(i);
}

function isHorizontalRule(line: string): boolean {
  const trimmed = line.trim();
  return /^(?:(?:\*\s*){3,}|(?:-\s*){3,}|(?:_\s*){3,})$/.test(trimmed);
}

function matchHeading(line: string): { level: 1 | 2 | 3 | 4 | 5 | 6; text: string } | null {
  const m = line.match(/^\s{0,3}(#{1,6})(?:\s+(.*?))?\s*#*\s*$/);
  if (!m) return null;
  const level = m[1].length as 1 | 2 | 3 | 4 | 5 | 6;
  const text = (m[2] ?? "").replace(/\s+#+\s*$/, "").trim();
  return { level, text };
}

function matchFenceStart(line: string): { marker: string; len: number; lang: string } | null {
  const m = line.match(/^\s{0,3}(`{3,}|~{3,})(.*)$/);
  if (!m) return null;
  const marker = m[1][0];
  const len = m[1].length;
  const info = m[2].trim();
  // Backtick info strings cannot contain backticks
  if (marker === "`" && info.includes("`")) return null;
  const lang = info.split(/\s+/)[0] ?? "";
  return { marker, len, lang };
}

interface ListMarkerMatch {
  indent: number;
  ordered: boolean;
  start: number;
  content: string;
}

function matchListMarker(line: string): ListMarkerMatch | null {
  const ul = line.match(/^([ \t]*)[-*+][ \t]+(.*)$/);
  if (ul) {
    return {
      indent: measureIndent(ul[1]),
      ordered: false,
      start: 1,
      content: ul[2],
    };
  }
  const ol = line.match(/^([ \t]*)(\d+)[.)][ \t]+(.*)$/);
  if (ol) {
    return {
      indent: measureIndent(ol[1]),
      ordered: true,
      start: Number.parseInt(ol[2], 10) || 1,
      content: ol[3],
    };
  }
  return null;
}

function splitTableRow(line: string): string[] {
  let trimmed = line.trim();
  if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
  if (trimmed.endsWith("|") && !trimmed.endsWith("\\|")) {
    trimmed = trimmed.slice(0, -1);
  }
  const cells: string[] = [];
  let buf = "";
  let inCode = false;
  let i = 0;
  while (i < trimmed.length) {
    const ch = trimmed[i];
    if (ch === "\\" && trimmed[i + 1] === "|") {
      buf += "|";
      i += 2;
      continue;
    }
    if (ch === "`") {
      inCode = !inCode;
      buf += ch;
      i++;
      continue;
    }
    if (ch === "|" && !inCode) {
      cells.push(buf.trim());
      buf = "";
      i++;
      continue;
    }
    buf += ch;
    i++;
  }
  cells.push(buf.trim());
  return cells;
}

function parseTableSeparator(line: string): TableAlign[] | null {
  const trimmed = line.trim();
  if (!trimmed.includes("-")) return null;
  if (!/^\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?$/.test(trimmed)) {
    return null;
  }
  return splitTableRow(trimmed).map((cell) => {
    const left = cell.startsWith(":");
    const right = cell.endsWith(":");
    if (left && right) return "center";
    if (right) return "right";
    if (left) return "left";
    return null;
  });
}

function isBlockStart(lines: string[], idx: number): boolean {
  const line = lines[idx];
  if (!line || !line.trim()) return true;
  if (matchFenceStart(line)) return true;
  if (matchHeading(line)) return true;
  if (isHorizontalRule(line)) return true;
  if (/^\s{0,3}>/.test(line)) return true;
  if (matchListMarker(line)) return true;
  if (
    line.includes("|") &&
    idx + 1 < lines.length &&
    parseTableSeparator(lines[idx + 1]) !== null
  ) {
    return true;
  }
  return false;
}

export function parseMarkdown(markdown: string): BlockNode[] {
  const normalized = markdown.replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  return parseLines(lines);
}

function parseLines(lines: string[]): BlockNode[] {
  const blocks: BlockNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Skip blank lines
    if (!line.trim()) {
      i++;
      continue;
    }

    // Fenced code block
    const fence = matchFenceStart(line);
    if (fence) {
      const codeLines: string[] = [];
      i++;
      const closeRe = new RegExp(`^\\s{0,3}${fence.marker}{${fence.len},}\\s*$`);
      while (i < lines.length && !closeRe.test(lines[i])) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++;
      blocks.push({
        type: "code",
        lang: fence.lang,
        value: codeLines.join("\n"),
      });
      continue;
    }

    // ATX Heading
    const heading = matchHeading(line);
    if (heading) {
      blocks.push({
        type: "heading",
        level: heading.level,
        children: parseMarkdownInline(heading.text),
      });
      i++;
      continue;
    }

    // Horizontal rule
    if (isHorizontalRule(line)) {
      blocks.push({ type: "hr" });
      i++;
      continue;
    }

    // Blockquote
    if (/^\s{0,3}>/.test(line)) {
      const quoteLines: string[] = [];
      while (i < lines.length) {
        const current = lines[i];
        if (/^\s{0,3}>/.test(current)) {
          quoteLines.push(current.replace(/^\s{0,3}> ?/, ""));
          i++;
        } else if (
          current.trim() &&
          quoteLines.length > 0 &&
          quoteLines[quoteLines.length - 1].trim() !== "" &&
          !isBlockStart(lines, i)
        ) {
          quoteLines.push(current);
          i++;
        } else {
          break;
        }
      }
      blocks.push({
        type: "blockquote",
        children: parseLines(quoteLines),
      });
      continue;
    }

    // GFM Table
    if (
      line.includes("|") &&
      i + 1 < lines.length &&
      parseTableSeparator(lines[i + 1]) !== null
    ) {
      const align = parseTableSeparator(lines[i + 1])!;
      const headerCells = splitTableRow(line);
      const colCount = Math.max(headerCells.length, align.length);
      const headers = Array.from({ length: colCount }, (_, idx) =>
        parseMarkdownInline(headerCells[idx] ?? ""),
      );
      const normalizedAlign: TableAlign[] = Array.from(
        { length: colCount },
        (_, idx) => align[idx] ?? null,
      );
      i += 2;
      const rows: InlineNode[][][] = [];
      while (
        i < lines.length &&
        lines[i].trim() !== "" &&
        lines[i].includes("|") &&
        !matchFenceStart(lines[i]) &&
        !matchHeading(lines[i])
      ) {
        const rawCells = splitTableRow(lines[i]);
        rows.push(
          Array.from({ length: colCount }, (_, idx) =>
            parseMarkdownInline(rawCells[idx] ?? ""),
          ),
        );
        i++;
      }
      blocks.push({
        type: "table",
        headers,
        align: normalizedAlign,
        rows,
      });
      continue;
    }

    // Ordered / Unordered List (with nested blocks support)
    const firstList = matchListMarker(line);
    if (firstList) {
      const baseIndent = firstList.indent;
      const ordered = firstList.ordered;
      const start = firstList.start;
      const items: ListItemNode[] = [];

      while (i < lines.length) {
        const marker = matchListMarker(lines[i]);
        if (!marker || marker.ordered !== ordered || marker.indent !== baseIndent) {
          break;
        }

        let itemContent = marker.content;
        let checked: boolean | undefined;
        const taskMatch = itemContent.match(/^\[([ xX])\]\s+(.*)$/);
        if (taskMatch) {
          checked = taskMatch[1].toLowerCase() === "x";
          itemContent = taskMatch[2];
        }

        i++;
        const childLines: string[] = [];
        let sawBlank = false;

        while (i < lines.length) {
          const nextLine = lines[i];
          if (!nextLine.trim()) {
            // Peek ahead to see if this list continues after blank line(s)
            let peek = i;
            while (peek < lines.length && !lines[peek].trim()) peek++;
            if (peek >= lines.length) {
              i = peek;
              break;
            }
            const nextNonBlank = lines[peek];
            const nextIndent = measureIndent(nextNonBlank);
            const nextMarker = matchListMarker(nextNonBlank);
            if (nextIndent > baseIndent) {
              sawBlank = true;
              childLines.push("");
              i++;
              continue;
            }
            if (
              nextMarker &&
              nextMarker.ordered === ordered &&
              nextMarker.indent === baseIndent
            ) {
              i = peek;
              break;
            }
            // Otherwise list ends
            i = peek;
            break;
          }

          const nextIndent = measureIndent(nextLine);
          if (nextIndent > baseIndent) {
            childLines.push(nextLine);
            i++;
            continue;
          }

          const nextMarker = matchListMarker(nextLine);
          if (nextMarker && nextMarker.indent <= baseIndent) {
            break;
          }

          if (isBlockStart(lines, i)) {
            break;
          }

          // Lazy continuation line belonging to this item
          if (!sawBlank && childLines.length === 0) {
            itemContent += " " + nextLine.trim();
            i++;
            continue;
          }
          break;
        }

        let nested: BlockNode[] = [];
        if (childLines.length > 0) {
          const nonBlankChildren = childLines.filter((l) => l.trim().length > 0);
          const minChildIndent = nonBlankChildren.reduce(
            (min, l) => Math.min(min, measureIndent(l)),
            Infinity,
          );
          const dedentBy = Number.isFinite(minChildIndent) ? minChildIndent : baseIndent + 2;
          const dedented = childLines.map((l) => (l.trim() ? stripIndent(l, dedentBy) : ""));
          nested = parseLines(dedented);
        }

        const itemNode: ListItemNode = {
          children: parseMarkdownInline(itemContent),
          nested,
        };
        if (checked !== undefined) {
          itemNode.checked = checked;
        }
        items.push(itemNode);
      }

      blocks.push({
        type: "list",
        ordered,
        start,
        items,
      });
      continue;
    }

    // Paragraph (consume consecutive plain text lines until blank or next block)
    const paraLines: string[] = [line];
    i++;
    while (i < lines.length && lines[i].trim() !== "" && !isBlockStart(lines, i)) {
      paraLines.push(lines[i]);
      i++;
    }
    blocks.push({
      type: "paragraph",
      children: parseMarkdownInline(paraLines.join("\n")),
    });
  }

  return blocks;
}

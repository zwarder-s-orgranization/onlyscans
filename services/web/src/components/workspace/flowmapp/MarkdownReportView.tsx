"use client";

import { Fragment, useMemo, type ReactNode } from "react";
import { Check } from "lucide-react";
import {
  parseMarkdown,
  type BlockNode,
  type InlineNode,
  type TableAlign,
} from "@/lib/markdown";

const SEVERITY_BADGE_MAP: Record<string, string> = {
  CRITICAL: "bg-[#000000] text-[#ffffff]",
  HIGH: "bg-[#ffd6e0] text-[#842029]",
  MEDIUM: "bg-[#fff3c4] text-[#664d03]",
  LOW: "bg-[#c5e0fb]/70 text-[#000000]",
  INFO: "border border-[#8c9baa]/55 bg-[#f8fafc] text-[#636f7b]",
  UNKNOWN: "border border-[#8c9baa]/55 bg-[#f8fafc] text-[#636f7b]",
};

const CATEGORY_TAGS = new Set(["SECRET", "SAST", "SCA"]);

function renderTextWithTags(text: string, enableTagBadges: boolean, keyPrefix: string): ReactNode {
  if (!enableTagBadges || !text.includes("[")) {
    return text;
  }
  const tokenRe = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN|SECRET|SAST|SCA)\][ \t]*/g;
  const parts: ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let partIdx = 0;

  while ((match = tokenRe.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(
        <Fragment key={`${keyPrefix}-t-${partIdx++}`}>
          {text.slice(lastIndex, match.index)}
        </Fragment>,
      );
    }
    const label = match[1];
    if (CATEGORY_TAGS.has(label)) {
      parts.push(
        <span
          key={`${keyPrefix}-b-${partIdx++}`}
          className="fm-mono mr-1.5 inline-flex shrink-0 whitespace-nowrap items-center rounded-full border border-[#8c9baa]/55 bg-[#f8fafc] px-2 py-[1px] align-baseline text-[10.5px] font-semibold tracking-[0.02em] text-[#222222]"
        >
          {label}
        </span>,
      );
    } else {
      const tone = SEVERITY_BADGE_MAP[label] ?? SEVERITY_BADGE_MAP.UNKNOWN;
      parts.push(
        <span
          key={`${keyPrefix}-b-${partIdx++}`}
          className={`mr-1.5 inline-flex shrink-0 whitespace-nowrap items-center rounded-full px-2 py-[1px] align-baseline text-[10.5px] font-semibold uppercase tracking-[0.02em] ${tone}`}
        >
          {label}
        </span>,
      );
    }
    lastIndex = match.index + match[0].length;
  }

  if (parts.length === 0) {
    return text;
  }
  if (lastIndex < text.length) {
    parts.push(
      <Fragment key={`${keyPrefix}-t-${partIdx++}`}>{text.slice(lastIndex)}</Fragment>,
    );
  }
  return parts;
}

function renderInlineNodes(
  nodes: InlineNode[],
  keyPrefix: string,
  enableTagBadges = false,
): ReactNode[] {
  return nodes.map((node, idx) => {
    const key = `${keyPrefix}-${idx}`;
    switch (node.type) {
      case "text":
        return (
          <Fragment key={key}>
            {renderTextWithTags(node.value, enableTagBadges, key)}
          </Fragment>
        );
      case "code":
        return (
          <code
            key={key}
            className="fm-mono rounded-[6px] border border-[#8c9baa]/35 bg-[#f8fafc] px-1.5 py-[1px] text-[12px] font-medium text-[#0050ff] [overflow-wrap:anywhere]"
          >
            {node.value}
          </code>
        );
      case "strong":
        return (
          <strong key={key} className="font-semibold text-[#000000]">
            {renderInlineNodes(node.children, key, true)}
          </strong>
        );
      case "em":
        return (
          <em key={key} className="italic">
            {renderInlineNodes(node.children, key, enableTagBadges)}
          </em>
        );
      case "del":
        return (
          <del key={key} className="text-[#636f7b] line-through">
            {renderInlineNodes(node.children, key, enableTagBadges)}
          </del>
        );
      case "link": {
        const isExternal = /^https?:\/\//i.test(node.href);
        return (
          <a
            key={key}
            href={node.href}
            target={isExternal ? "_blank" : undefined}
            rel={isExternal ? "noopener noreferrer" : undefined}
            className="fm-focus rounded-[3px] text-[#0050ff] underline decoration-[#0080ff]/45 underline-offset-[3px] transition-colors hover:text-[#0080ff] hover:decoration-[#0080ff] [overflow-wrap:anywhere]"
          >
            {renderInlineNodes(node.children, key, false)}
          </a>
        );
      }
      case "br":
        return <br key={key} />;
    }
  });
}

function alignClass(align: TableAlign): string {
  if (align === "center") return "text-center";
  if (align === "right") return "text-right";
  return "text-left";
}

function renderBlocks(blocks: BlockNode[], keyPrefix: string, depth = 0): ReactNode[] {
  return blocks.map((block, idx) => {
    const key = `${keyPrefix}-${idx}`;
    switch (block.type) {
      case "heading": {
        const content = renderInlineNodes(block.children, key);
        if (block.level === 1) {
          return (
            <h1
              key={key}
              className="mt-6 mb-3 border-b border-[#8c9baa]/35 pb-2 text-[19px] font-bold leading-[1.3] tracking-[-0.025em] text-[#000000] first:mt-0 sm:text-[21px] [overflow-wrap:anywhere]"
            >
              {content}
            </h1>
          );
        }
        if (block.level === 2) {
          return (
            <h2
              key={key}
              className="mt-6 mb-2.5 border-b border-[#8c9baa]/25 pb-1.5 text-[15.5px] font-bold leading-[1.35] tracking-[-0.02em] text-[#000000] first:mt-0 [overflow-wrap:anywhere]"
            >
              {content}
            </h2>
          );
        }
        if (block.level === 3) {
          return (
            <h3
              key={key}
              className="mt-5 mb-2 text-[14px] font-semibold leading-[1.4] tracking-[-0.015em] text-[#000000] first:mt-0 [overflow-wrap:anywhere]"
            >
              {content}
            </h3>
          );
        }
        return (
          <h4
            key={key}
            className="mt-4 mb-1.5 text-[13px] font-semibold leading-[1.4] text-[#222222] first:mt-0 [overflow-wrap:anywhere]"
          >
            {content}
          </h4>
        );
      }

      case "paragraph":
        return (
          <p
            key={key}
            className="my-2.5 max-w-[78ch] text-[13.5px] leading-[1.6] text-[#222222] first:mt-0 last:mb-0 [overflow-wrap:anywhere]"
          >
            {renderInlineNodes(block.children, key)}
          </p>
        );

      case "code":
        return (
          <div
            key={key}
            className="fm-code-block my-3 overflow-hidden rounded-[12px] first:mt-0 last:mb-0"
          >
            {block.lang && (
              <div className="border-b border-[#8c9baa]/25 px-3.5 py-1.5 text-[11px] font-medium text-[#636f7b]">
                <span className="fm-mono">{block.lang}</span>
              </div>
            )}
            <pre className="fm-scroll fm-mono overflow-x-auto p-3.5 text-[12px] leading-[1.55]">
              <code>{block.value}</code>
            </pre>
          </div>
        );

      case "blockquote":
        return (
          <blockquote
            key={key}
            className="my-3 rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] px-4 py-3 text-[13px] leading-[1.55] text-[#222222] first:mt-0 last:mb-0"
          >
            {renderBlocks(block.children, key, depth + 1)}
          </blockquote>
        );

      case "hr":
        return <hr key={key} className="my-5 border-0 border-t border-[#8c9baa]/35" />;

      case "list": {
        const isNested = depth > 0;
        const hasTaskItems = block.items.some((item) => item.checked !== undefined);
        const ListTag = block.ordered ? "ol" : "ul";
        const listClass = hasTaskItems
          ? isNested
            ? "mt-1.5 space-y-1 pl-1 list-none"
            : "my-2.5 space-y-2 pl-1 list-none first:mt-0 last:mb-0"
          : block.ordered
            ? isNested
              ? "fm-tnum mt-1.5 list-decimal space-y-1 pl-5 text-[13px] marker:font-semibold marker:text-[#636f7b]"
              : "fm-tnum my-2.5 list-decimal space-y-2 pl-5 first:mt-0 last:mb-0 marker:font-semibold marker:text-[#636f7b]"
            : isNested
              ? "mt-1.5 list-[circle] space-y-1 pl-4 text-[13px] marker:text-[#8c9baa]"
              : "my-2.5 list-disc space-y-2 pl-5 first:mt-0 last:mb-0 marker:text-[#636f7b]";

        return (
          <ListTag
            key={key}
            start={block.ordered && block.start !== 1 ? block.start : undefined}
            className={listClass}
          >
            {block.items.map((item, itemIdx) => {
              const itemKey = `${key}-li-${itemIdx}`;
              return (
                <li
                  key={itemKey}
                  className={`leading-[1.55] text-[#222222] [overflow-wrap:anywhere] ${
                    isNested ? "text-[12.5px] text-[#636f7b]" : "text-[13.5px]"
                  }`}
                >
                  {item.checked !== undefined ? (
                    <div className="flex items-start gap-2">
                      <span
                        aria-label={item.checked ? "Выполнено" : "Не выполнено"}
                        className={`mt-[3px] inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-[4px] border ${
                          item.checked
                            ? "border-[#0080ff] bg-[#0080ff] text-[#ffffff]"
                            : "border-[#8c9baa]/70 bg-[#ffffff]"
                        }`}
                      >
                        {item.checked && (
                          <Check className="h-3 w-3 stroke-[2.5]" aria-hidden="true" />
                        )}
                      </span>
                      <div className="min-w-0 flex-1">
                        <span>{renderInlineNodes(item.children, itemKey)}</span>
                        {item.nested.length > 0 &&
                          renderBlocks(item.nested, `${itemKey}-n`, depth + 1)}
                      </div>
                    </div>
                  ) : (
                    <>
                      <span>{renderInlineNodes(item.children, itemKey)}</span>
                      {item.nested.length > 0 &&
                        renderBlocks(item.nested, `${itemKey}-n`, depth + 1)}
                    </>
                  )}
                </li>
              );
            })}
          </ListTag>
        );
      }

      case "table":
        return (
          <div
            key={key}
            className="fm-scroll my-3.5 overflow-x-auto rounded-[12px] border border-[#8c9baa]/45 first:mt-0 last:mb-0"
          >
            <table className="fm-tnum min-w-full border-collapse text-[12.5px]">
              <thead className="bg-[#f8fafc]">
                <tr>
                  {block.headers.map((cell, cellIdx) => (
                    <th
                      key={`${key}-h-${cellIdx}`}
                      scope="col"
                      className={`border-b border-[#8c9baa]/35 px-3 py-2 font-semibold text-[#000000] [overflow-wrap:anywhere] ${alignClass(block.align[cellIdx] ?? null)}`}
                    >
                      {renderInlineNodes(cell, `${key}-h-${cellIdx}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#8c9baa]/25">
                {block.rows.map((row, rowIdx) => (
                  <tr key={`${key}-r-${rowIdx}`} className="bg-[#ffffff]">
                    {row.map((cell, cellIdx) => (
                      <td
                        key={`${key}-r-${rowIdx}-c-${cellIdx}`}
                        className={`px-3 py-2 align-top text-[#222222] [overflow-wrap:anywhere] ${alignClass(block.align[cellIdx] ?? null)}`}
                      >
                        {renderInlineNodes(cell, `${key}-r-${rowIdx}-c-${cellIdx}`)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
    }
  });
}

export interface MarkdownReportViewProps {
  content: string;
}

export function MarkdownReportView({ content }: MarkdownReportViewProps) {
  const blocks = useMemo(() => parseMarkdown(content), [content]);

  if (blocks.length === 0) {
    return (
      <p className="py-8 text-center text-[13px] text-[#636f7b]">Отчёт пуст.</p>
    );
  }

  return <div className="min-w-0">{renderBlocks(blocks, "md")}</div>;
}

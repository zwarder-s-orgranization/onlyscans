"use client";

import {
  Archive,
  Clock,
  FileJson2,
  FileText,
  Filter,
  GitBranch,
  GitCompareArrows,
  GitFork,
  Globe,
  KeyRound,
  Mail,
  PackageSearch,
  Play,
  Plug,
  Regex,
  Scale,
  Send,
  ShieldAlert,
  Sparkles,
  Split,
  Webhook,
} from "lucide-react";
import type { NodeIconKey } from "@/data/canvas-nodes-catalog";

export function NodeCategoryIcon({
  iconKey,
  className = "h-4 w-4",
}: {
  iconKey: NodeIconKey;
  className?: string;
}) {
  switch (iconKey) {
    case "play":
      return <Play className={className} aria-hidden="true" />;
    case "webhook":
      return <Webhook className={className} aria-hidden="true" />;
    case "clock":
      return <Clock className={className} aria-hidden="true" />;
    case "archive":
      return <Archive className={className} aria-hidden="true" />;
    case "git":
      return <GitBranch className={className} aria-hidden="true" />;
    case "key":
      return <KeyRound className={className} aria-hidden="true" />;
    case "package":
      return <PackageSearch className={className} aria-hidden="true" />;
    case "shield-code":
      return <ShieldAlert className={className} aria-hidden="true" />;
    case "file-json":
      return <FileJson2 className={className} aria-hidden="true" />;
    case "scale":
      return <Scale className={className} aria-hidden="true" />;
    case "git-branch":
      return <GitFork className={className} aria-hidden="true" />;
    case "filter":
      return <Filter className={className} aria-hidden="true" />;
    case "regex":
      return <Regex className={className} aria-hidden="true" />;
    case "split":
      return <Split className={className} aria-hidden="true" />;
    case "diff":
      return <GitCompareArrows className={className} aria-hidden="true" />;
    case "sparkles":
      return <Sparkles className={className} aria-hidden="true" />;
    case "file-text":
      return <FileText className={className} aria-hidden="true" />;
    case "send":
      return <Send className={className} aria-hidden="true" />;
    case "globe":
      return <Globe className={className} aria-hidden="true" />;
    case "mail":
      return <Mail className={className} aria-hidden="true" />;
    case "plug":
      return <Plug className={className} aria-hidden="true" />;
    default:
      return <Play className={className} aria-hidden="true" />;
  }
}

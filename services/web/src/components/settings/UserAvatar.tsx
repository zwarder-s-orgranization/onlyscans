"use client";

import { User } from "lucide-react";

export function UserAvatar({
  size = 36,
  className = "",
}: {
  seed?: string;
  size?: number;
  className?: string;
}) {
  const iconSize = Math.round(size * 0.46);

  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 items-center justify-center rounded-full bg-[#f1f5f9] text-[#222222] select-none ${className}`}
      style={{ width: size, height: size }}
    >
      <User
        width={iconSize}
        height={iconSize}
        className="stroke-[1.75]"
        aria-hidden="true"
      />
    </span>
  );
}

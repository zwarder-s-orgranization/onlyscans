import type { Metadata } from "next";
import { Suspense } from "react";
import { SettingsShell } from "@/components/settings/SettingsShell";

export const metadata: Metadata = {
  title: "Настройки и профиль — onlyscans",
  description:
    "Профиль пользователя, RBAC, masked-секреты, Scoped Tokens, AI-провайдер и MCP-серверы onlyscans.",
};

export default function SettingsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-dvh items-center justify-center bg-[#ffffff] text-[14px] text-[#636f7b]">
          Загрузка настроек…
        </div>
      }
    >
      <SettingsShell />
    </Suspense>
  );
}

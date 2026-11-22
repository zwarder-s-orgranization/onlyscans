"use client";

import { useEffect, useState, type FormEvent } from "react";
import { Check, Eye, Lock, LogOut, ShieldCheck } from "lucide-react";
import { ROLE_LABELS, type UserRole } from "@/data/workflows-workspace-data";
import { useWorkspacePreview } from "@/components/workspace/WorkspacePreviewContext";
import { RBAC_MATRIX } from "@/data/settings-data";
import { clearSession, readSession, type Session } from "@/lib/session";
import { UserAvatar } from "./UserAvatar";

interface ProfileTabProps {
  role: UserRole;
  onChangeRole: (next: UserRole) => void;
  onNotice: (message: string) => void;
  onLogout?: () => void;
}

const ROLE_OPTIONS: Array<{ id: UserRole; label: string; hint: string }> = [
  { id: "owner", label: "owner", hint: "Полный доступ: секреты, токены, MCP" },
  { id: "editor", label: "editor", hint: "Workflows, запуски и секреты" },
  { id: "viewer", label: "viewer", hint: "Только чтение отчётов и графов" },
];

function formatSessionExpiry(iso?: string): string {
  if (!iso) return "срок действия не указан";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ProfileTab({ role, onChangeRole, onNotice, onLogout }: ProfileTabProps) {
  const { email: accountEmail } = useWorkspacePreview();
  const baseUser = ROLE_LABELS[role];
  const [displayName, setDisplayName] = useState(accountEmail || baseUser.name);
  const [email, setEmail] = useState(accountEmail || baseUser.email);
  const [editingProfile, setEditingProfile] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [sessionInfo, setSessionInfo] = useState<Session | null>(null);

  useEffect(() => {
    setDisplayName(accountEmail || ROLE_LABELS[role].name);
    setEmail(accountEmail || ROLE_LABELS[role].email);
    setEditingProfile(false);
    setProfileError(null);
    setSessionInfo(readSession());
  }, [accountEmail, role]);

  const handleSaveProfile = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const cleanName = displayName.trim();
    const cleanEmail = email.trim();
    if (cleanName.length < 2) {
      setProfileError("Укажите имя не короче 2 символов.");
      return;
    }
    if (!cleanEmail.includes("@") || !cleanEmail.includes(".")) {
      setProfileError("Введите корректный адрес электронной почты.");
      return;
    }
    setProfileError(null);
    setEditingProfile(false);
    onNotice("Сервер хранит почту и роль из входа. Имя на экране локальное и не записывается.");
  };

  const handleLogout = () => {
    if (onLogout) {
      onLogout();
      return;
    }
    clearSession();
    onNotice("Сессия завершена");
  };

  const authModeLabel = sessionInfo?.authMode
    ? `AUTH_MODE=${sessionInfo.authMode.toLowerCase()}`
    : "AUTH_MODE=local";

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#8c9baa]/45 pb-5">
        <div className="min-w-0">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Профиль пользователя
          </h1>
          <p className="mt-1 text-[14px] text-[#636f7b]">
            Учётные данные, активная роль RBAC и параметры сессии onlyscans.
          </p>
        </div>

        <span className="fm-mono inline-flex items-center gap-1.5 rounded-full border border-[#0080ff]/45 bg-[#c5e0fb]/35 px-3 py-1.5 text-[12px] font-semibold text-[#000000]">
          <ShieldCheck className="h-3.5 w-3.5 text-[#0080ff]" aria-hidden="true" />
          Роль: {role}
        </span>
      </div>

      {/* Section 1: Account card */}
      <section aria-labelledby="profile-account-heading">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2
            id="profile-account-heading"
            className="text-[16px] font-semibold tracking-[-0.02em] text-[#000000]"
          >
            Личные данные
          </h2>
          {!editingProfile && (
            <button
              type="button"
              onClick={() => setEditingProfile(true)}
              className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
            >
              Изменить
            </button>
          )}
        </div>

        <form
          onSubmit={handleSaveProfile}
          className="mt-3 rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] p-5"
        >
          <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
            <UserAvatar
              seed={accountEmail || displayName}
              size={64}
              className="ring-1 ring-[#8c9baa]/50"
            />

            <div className="grid min-w-0 flex-1 gap-4 sm:grid-cols-2">
              <div className="min-w-0">
                <label
                  htmlFor="profile-name-input"
                  className="block text-[12px] font-medium text-[#636f7b]"
                >
                  Имя пользователя
                </label>
                {editingProfile ? (
                  <input
                    id="profile-name-input"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[14px]"
                  />
                ) : (
                  <p
                    title={displayName}
                    className="mt-1 truncate text-[15px] font-semibold text-[#000000]"
                  >
                    {displayName}
                  </p>
                )}
              </div>

              <div className="min-w-0">
                <label
                  htmlFor="profile-email-input"
                  className="block text-[12px] font-medium text-[#636f7b]"
                >
                  Email
                </label>
                {editingProfile ? (
                  <input
                    id="profile-email-input"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[14px]"
                  />
                ) : (
                  <p title={email} className="fm-mono mt-1 truncate text-[13.5px] text-[#222222]">
                    {email}
                  </p>
                )}
              </div>
            </div>
          </div>

          {profileError && (
            <p role="alert" className="mt-3 text-[13px] font-medium text-[#b42318]">
              {profileError}
            </p>
          )}

          {editingProfile && (
            <div className="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
              <button
                type="button"
                onClick={() => {
                  setDisplayName(accountEmail || baseUser.name);
                  setEmail(accountEmail || baseUser.email);
                  setProfileError(null);
                  setEditingProfile(false);
                }}
                className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
              >
                Отмена
              </button>
              <button
                type="submit"
                className="fm-btn-ink fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-semibold"
              >
                Сохранить профиль
              </button>
            </div>
          )}
        </form>
      </section>

      {/* Section 2: RBAC Matrix */}
      <section aria-labelledby="profile-rbac-heading">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2
              id="profile-rbac-heading"
              className="text-[16px] font-semibold tracking-[-0.02em] text-[#000000]"
            >
              Права доступа (RBAC)
            </h2>
            <p className="mt-0.5 text-[13px] text-[#636f7b]">
              Матрица edge-gateway определяет доступ к секретам, токенам и MCP-подключениям.
            </p>
          </div>

          <div
            role="group"
            aria-label="Активная роль"
            className="inline-flex flex-wrap items-center gap-1 rounded-full border border-[#8c9baa]/55 bg-[#ffffff] p-1"
          >
            {ROLE_OPTIONS.map((opt) => {
              const active = role === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    if (opt.id !== role) {
                      onNotice("Роль выдаёт сервер при входе. Здесь её сменить нельзя.");
                      return;
                    }
                    onChangeRole(opt.id);
                  }}
                  aria-pressed={active}
                  title={opt.hint}
                  className={`fm-focus fm-mono min-h-[32px] cursor-pointer rounded-full px-3 text-[12px] font-semibold transition-colors ${
                    active
                      ? "bg-[#000000] text-[#ffffff]"
                      : "text-[#636f7b] hover:text-[#000000]"
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="mt-3 overflow-hidden rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff]">
          <div className="divide-y divide-[#8c9baa]/35">
            {RBAC_MATRIX.map((row) => {
              const level = row[role];
              return (
                <div
                  key={row.area}
                  className="flex flex-col gap-2 px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <p className="text-[14px] font-semibold text-[#000000]">{row.area}</p>
                    <p className="mt-0.5 text-[12.5px] text-[#636f7b]">{row.detail}</p>
                  </div>

                  <div className="shrink-0">
                    {level === "allow" && (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-[#c8f0d8]/70 px-2.5 py-1 text-[12px] font-semibold text-[#0f5132]">
                        <Check className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
                        Полный доступ
                      </span>
                    )}
                    {level === "readonly" && (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-[#fff3c4]/85 px-2.5 py-1 text-[12px] font-semibold text-[#664d03]">
                        <Eye className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                        Только чтение
                      </span>
                    )}
                    {level === "deny" && (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-[#ffd6e0]/70 px-2.5 py-1 text-[12px] font-semibold text-[#842029]">
                        <Lock className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                        Нет доступа
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Section 3: Session & Security */}
      <section aria-labelledby="profile-session-heading">
        <h2
          id="profile-session-heading"
          className="text-[16px] font-semibold tracking-[-0.02em] text-[#000000]"
        >
          Сессия и безопасность
        </h2>

        <div className="mt-3 rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] p-5">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="fm-mono rounded-full border border-[#8c9baa]/55 px-2.5 py-0.5 text-[12px] font-semibold text-[#222222]">
                  {authModeLabel}
                </span>
                <span className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-[#0f5132]">
                  <span className="h-2 w-2 rounded-full bg-[#198754]" aria-hidden="true" />
                  Активная сессия
                </span>
              </div>
              <p className="fm-tnum mt-1.5 text-[13px] text-[#636f7b]">
                Bearer JWT · Сессия действительна до {formatSessionExpiry(sessionInfo?.expiresAt)}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleLogout}
                className="fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-2 rounded-full border border-dashed border-[#8c9baa] bg-[#ffffff] px-4 text-[13px] font-medium text-[#222222] transition-colors hover:border-[#b42318] hover:bg-[#ffd6e0]/35 hover:text-[#000000]"
              >
                <LogOut className="h-4 w-4 stroke-[1.6]" aria-hidden="true" />
                Выйти
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

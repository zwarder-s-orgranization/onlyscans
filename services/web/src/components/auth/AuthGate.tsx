"use client";

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { InkThemeToggle } from "@/components/theme/InkThemeToggle";
import { useWorkspacePreview } from "@/components/workspace/WorkspacePreviewContext";
import { ApiError, gql, QUERIES } from "@/lib/api";
import { clearSession, readSession, writeSession, type Session } from "@/lib/session";
import type { UserRole } from "@/data/workflows-workspace-data";

function asRole(value: string | null | undefined): UserRole {
  const role = (value || "viewer").toLowerCase();
  if (role === "owner" || role === "editor" || role === "viewer") return role;
  return "viewer";
}

interface MeResponse {
  me: {
    subject: string;
    email?: string | null;
    role?: string | null;
    authMode?: string | null;
  };
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { setRole, setEmail } = useWorkspacePreview();
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<Session | null>(null);

  useEffect(() => {
    let cancelled = false;

    const syncFromStorage = () => {
      const next = readSession();
      setSession(next);
      if (next) {
        setRole(next.role);
        setEmail(next.email);
      }
    };

    const current = readSession();
    if (!current) {
      setSession(null);
      setReady(true);
    } else {
      setSession(current);
      setRole(current.role);
      setEmail(current.email);
      void gql<MeResponse>(QUERIES.me)
        .then((data) => {
          if (cancelled) return;
          const authoritativeRole = asRole(data.me.role);
          const authoritativeEmail = data.me.email || data.me.subject || current.email;
          const nextSession: Session = {
            ...current,
            email: authoritativeEmail,
            role: authoritativeRole,
            subject: data.me.subject,
            authMode: data.me.authMode ?? current.authMode,
          };
          if (
            nextSession.email !== current.email ||
            nextSession.role !== current.role ||
            nextSession.subject !== current.subject ||
            nextSession.authMode !== current.authMode
          ) {
            writeSession(nextSession);
          }
          setRole(nextSession.role);
          setEmail(nextSession.email);
          setSession(nextSession);
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          if (
            err instanceof ApiError &&
            (err.code === "UNAUTHENTICATED" || err.status === 401)
          ) {
            clearSession();
            setSession(null);
          }
        })
        .finally(() => {
          if (!cancelled) setReady(true);
        });
    }

    window.addEventListener("secflow-auth", syncFromStorage);
    return () => {
      cancelled = true;
      window.removeEventListener("secflow-auth", syncFromStorage);
    };
  }, [setEmail, setRole]);

  if (!ready) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-[#ffffff] text-[14px] text-[#636f7b]">
        Проверяем сессию…
      </div>
    );
  }
  if (!session) {
    return (
      <LoginScreen
        onSuccess={(next) => {
          writeSession(next);
          setRole(next.role);
          setEmail(next.email);
          setSession(next);
        }}
      />
    );
  }
  return children;
}

const IS_DEV = process.env.NODE_ENV !== "production";

function LoginScreen({ onSuccess }: { onSuccess: (session: Session) => void }) {
  const [email, setEmailValue] = useState(IS_DEV ? "owner@secflow.local" : "");
  const [password, setPassword] = useState(IS_DEV ? "secflow" : "");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError("");
    void gql<{
      login: {
        accessToken: string;
        expiresAt: string;
        actor: {
          subject?: string | null;
          email?: string | null;
          role?: string | null;
          authMode?: string | null;
        };
      };
    }>(QUERIES.login, { input: { email, password } }, { auth: false })
      .then((data) => {
        onSuccess({
          accessToken: data.login.accessToken,
          email: data.login.actor.email || email,
          role: asRole(data.login.actor.role),
          expiresAt: data.login.expiresAt,
          subject: data.login.actor.subject ?? undefined,
          authMode: data.login.actor.authMode ?? "LOCAL",
        });
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError) {
          if (err.code === "FAILED_PRECONDITION") {
            setError(
              "Локальный вход отключён на сервере (AUTH_MODE=oidc). Войдите через корпоративный OIDC-провайдер.",
            );
            return;
          }
          if (err.code === "UNAUTHENTICATED" || err.status === 401) {
            setError("Неверная почта или пароль.");
            return;
          }
          setError(err.message);
          return;
        }
        setError("Не удалось войти");
      })
      .finally(() => setPending(false));
  };

  return (
    <div className="flex min-h-dvh items-center justify-center bg-[#ffffff] px-4 text-[#000000]">
      <form
        onSubmit={submit}
        className="w-full max-w-[420px] rounded-[24px] border border-[#8c9baa]/60 p-6"
      >
        <div className="mb-3 flex items-center justify-between gap-2">
          <img
            src="/onlyscans-logo.png"
            alt="onlyscans"
            width={151}
            height={26}
            className="fm-brand-logo h-[26px] w-auto select-none"
          />
          <InkThemeToggle />
        </div>
        <h1 className="text-[24px] font-semibold tracking-[-0.04em]">Вход</h1>
        <p className="mt-2 text-[14px] text-[#636f7b]">
          Локальный аккаунт стенда. После входа сценарии читаются с сервера.
        </p>
        <label className="mt-5 block text-[13px] font-medium" htmlFor="secflow-email">
          Почта
        </label>
        <input
          id="secflow-email"
          type="email"
          value={email}
          onChange={(event) => setEmailValue(event.target.value)}
          className="mt-1 h-11 w-full rounded-full border border-[#8c9baa] px-4 text-[16px] outline-none focus:border-[#0080ff] sm:text-[14px]"
          autoComplete="username"
          required
        />
        <label className="mt-3 block text-[13px] font-medium" htmlFor="secflow-password">
          Пароль
        </label>
        <input
          id="secflow-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="mt-1 h-11 w-full rounded-full border border-[#8c9baa] px-4 text-[16px] outline-none focus:border-[#0080ff] sm:text-[14px]"
          autoComplete="current-password"
          required
        />
        {error && (
          <p role="alert" className="mt-3 text-[13px] text-[#dc2626]">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={pending}
          className="mt-5 inline-flex h-11 w-full cursor-pointer items-center justify-center rounded-full bg-[#000000] text-[14px] font-semibold text-[#ffffff] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pending ? "Входим…" : "Войти"}
        </button>
      </form>
    </div>
  );
}

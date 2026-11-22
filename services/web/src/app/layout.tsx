import type { Metadata, Viewport } from "next";
import { IBM_Plex_Sans, JetBrains_Mono } from "next/font/google";
import "@xyflow/react/dist/style.css";
import "./globals.css";
import "./flowmapp/flowmapp.css";
import { AuthGate } from "@/components/auth/AuthGate";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import { WorkspacePreviewProvider } from "@/components/workspace/WorkspacePreviewContext";

const ibmPlexSans = IBM_Plex_Sans({
  subsets: ["cyrillic", "latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-fm-sans",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["cyrillic", "latin"],
  weight: ["400", "500", "600"],
  variable: "--font-fm-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "onlyscans — AI Security Workflow",
  description:
    "Визуальная платформа автоматизации проверок безопасности для Cyber Garden 2026 (Банк «Центр-инвест»).",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#000000" },
  ],
};

const THEME_INIT_SCRIPT = `(function(){try{var t=localStorage.getItem('secflow-theme');if(t==='dark'){document.documentElement.dataset.theme='dark';document.documentElement.style.colorScheme='dark';}}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="ru"
      suppressHydrationWarning
      className={`${ibmPlexSans.variable} ${jetbrainsMono.variable}`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body
        className={`flowmapp-root min-h-dvh antialiased ${ibmPlexSans.variable} ${jetbrainsMono.variable}`}
      >
        <ThemeProvider>
          <WorkspacePreviewProvider>
            <AuthGate>{children}</AuthGate>
          </WorkspacePreviewProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}

"use client";

import {
  Activity,
  Bell,
  ClipboardList,
  FileSearch,
  HeartPulse,
  History,
  LayoutDashboard,
  Link2,
  Menu,
  PlayCircle,
  Settings,
  ShieldHalf,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { AuthBanner } from "@/components/shell/auth-banner";
import { ConnectionStatus } from "@/components/shell/connection-status";
import { cn } from "@/lib/utils";

export const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/analyze", label: "Message analyzer", icon: FileSearch },
  { href: "/urls", label: "URL analyzer", icon: Link2 },
  { href: "/history", label: "Scan history", icon: History },
  { href: "/events", label: "Security events", icon: Bell },
  { href: "/incidents", label: "Incidents", icon: ClipboardList },
  { href: "/replay", label: "Attack replay", icon: PlayCircle },
  { href: "/system-health", label: "System health", icon: HeartPulse },
  { href: "/settings", label: "Settings & privacy", icon: Settings },
] as const;

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <ul className="flex flex-col gap-0.5">
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <li key={href}>
            <Link
              href={href}
              onClick={onNavigate}
              aria-current={active ? "page" : undefined}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active ? "bg-accent/10 text-accent" : "text-muted hover:bg-surface-2 hover:text-fg",
              )}
            >
              <Icon className="size-4 shrink-0" aria-hidden />
              {label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2 px-3 font-semibold tracking-tight">
      <ShieldHalf className="size-6 text-accent" aria-hidden />
      <span>
        Sentinel<span className="text-accent">AI</span>
      </span>
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const current = NAV_ITEMS.find((n) => pathname.startsWith(n.href));

  return (
    <div className="flex min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-fg">
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col gap-6 border-r border-border bg-surface px-3 py-5 lg:flex">
        <Brand />
        <nav aria-label="Main navigation" className="flex-1 overflow-y-auto">
          <NavLinks />
        </nav>
        <p className="px-3 text-[11px] leading-relaxed text-subtle">
          Risk scores are evidence indices, not probabilities. Indicators are not proof.
        </p>
      </aside>

      {/* Mobile drawer */}
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button type="button" aria-label="Close navigation" className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 flex w-72 flex-col gap-6 border-r border-border bg-surface px-3 py-5">
            <div className="flex items-center justify-between">
              <Brand />
              <button type="button" onClick={() => setOpen(false)} aria-label="Close navigation" className="rounded-md p-2 text-muted hover:text-fg">
                <X className="size-5" />
              </button>
            </div>
            <nav aria-label="Main navigation">
              <NavLinks onNavigate={() => setOpen(false)} />
            </nav>
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-bg/90 px-4 backdrop-blur sm:px-6">
          <button
            type="button"
            className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg lg:hidden"
            aria-label="Open navigation"
            aria-expanded={open}
            onClick={() => setOpen(true)}
          >
            <Menu className="size-5" />
          </button>
          <div className="flex min-w-0 items-center gap-2 text-sm text-muted">
            <Activity className="size-4 text-accent" aria-hidden />
            <span className="truncate">{current?.label ?? "SentinelAI"}</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <ConnectionStatus />
          </div>
        </header>
        <AuthBanner />
        <main id="main" className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  );
}

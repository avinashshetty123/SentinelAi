"use client";

import { useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { onTokenChange } from "@/lib/auth";

/** Shown when the backend requires an operator token that has not been provided (AUTH_MODE=token). */
export function AuthBanner() {
  const [version, setVersion] = useState(0);
  useEffect(() => onTokenChange(() => setVersion((v) => v + 1)), []);
  const { data } = useQuery({ queryKey: ["auth-session", version], queryFn: api.authSession, staleTime: 60_000 });
  if (!data || !data.token_required || data.authenticated) return null;
  return (
    <div role="status" className="flex flex-wrap items-center gap-2 border-b border-risk-medium/30 bg-risk-medium/10 px-6 py-2 text-xs text-risk-medium">
      <KeyRound className="size-4" aria-hidden />
      This deployment requires an operator token.
      <Link href="/settings" className="font-medium underline underline-offset-2">
        Enter it in Settings
      </Link>
    </div>
  );
}

"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { useState, useSyncExternalStore } from "react";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/form";
import { Notice } from "@/components/ui/states";
import { api } from "@/lib/api";
import { getToken, onTokenChange, setToken } from "@/lib/auth";

function Setting({ name, value, env }: { name: string; value: string; env: string }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border py-3 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="text-sm">{name}</p>
        <p className="font-mono text-[11px] text-subtle">{env}</p>
      </div>
      <Badge>{value}</Badge>
    </div>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");
  const [show, setShow] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const hasToken = useSyncExternalStore(onTokenChange, () => Boolean(getToken()), () => false);
  const session = useQuery({ queryKey: ["auth-session", hasToken], queryFn: api.authSession });
  const status = useQuery({ queryKey: ["system-status"], queryFn: api.systemStatus, retry: false });

  const save = async () => {
    setToken(draft.trim() || null);
    setDraft("");
    const result = await queryClient.fetchQuery({ queryKey: ["auth-session", "check", Date.now()], queryFn: api.authSession });
    setMessage(result.authenticated ? "Token accepted by the server." : "The server did not accept this token.");
    queryClient.invalidateQueries();
  };

  const privacy = status.data?.privacy;
  return (
    <>
      <PageHeader title="Settings & privacy" description="Session access, and the privacy and retention configuration of this deployment." />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><KeyRound className="size-4" aria-hidden /> Operator access</CardTitle>
            <CardDescription>
              Server auth mode: <strong>{session.data?.auth_mode ?? "…"}</strong>.{" "}
              {session.data?.auth_mode === "token"
                ? "All API calls require the operator token configured on the server (ADMIN_API_TOKEN)."
                : "Open mode: no token is required (local development or an explicitly acknowledged public demo)."}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void save(); }}>
              <Label htmlFor="token">Operator token</Label>
              <div className="flex gap-2">
                <Input id="token" type={show ? "text" : "password"} autoComplete="off" value={draft}
                       onChange={(e) => setDraft(e.target.value)} placeholder={hasToken ? "•••••• (token set for this tab)" : "Paste token"} />
                <Button variant="ghost" size="icon" onClick={() => setShow((v) => !v)} aria-label={show ? "Hide token" : "Show token"}>
                  {show ? <EyeOff /> : <Eye />}
                </Button>
              </div>
              <div className="flex gap-2">
                <Button type="submit" size="sm" disabled={!draft.trim()}>Save token</Button>
                {hasToken && (
                  <Button variant="outline" size="sm" onClick={() => { setToken(null); setMessage("Token cleared."); queryClient.invalidateQueries(); }}>
                    <Trash2 aria-hidden /> Clear token
                  </Button>
                )}
              </div>
            </form>
            {message && <Notice tone={message.includes("not") ? "warning" : "success"}>{message}</Notice>}
            <p className="text-[11px] text-subtle">
              Stored in this tab&apos;s sessionStorage only and sent as an Authorization header — never as a cookie. Closing the tab forgets it.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" aria-hidden /> Privacy & retention</CardTitle>
            <CardDescription>Configured on the server through environment variables; shown here read-only.</CardDescription>
          </CardHeader>
          <CardContent>
            {privacy ? (
              <>
                <Setting name="Raw message text stored" value="Never" env="(not configurable)" />
                <Setting name="Evidence excerpts stored with findings" value={privacy.finding_excerpts_stored ? "Yes" : "No"} env="STORE_FINDING_EXCERPTS" />
                <Setting name="AI summaries stored with scans" value={privacy.ai_summaries_stored ? "Yes" : "No"} env="STORE_AI_SUMMARIES" />
                <Setting name="Scan retention" value={`${String(privacy.scan_retention_days)} days`} env="SCAN_RETENTION_DAYS" />
                <Setting name="AI explanations" value={status.data?.groq.status === "active" ? `On · ${status.data.groq.model}` : "Off"} env="GROQ_ENABLED / GROQ_API_KEY" />
                <Setting name="Demo features" value={status.data?.demo_mode ? "Enabled" : "Disabled"} env="DEMO_MODE_ENABLED" />
              </>
            ) : (
              <p className="text-sm text-muted">Server configuration unavailable{status.isError ? " (check your token or the API URL)" : "…"}.</p>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>What happens to submitted data</CardTitle></CardHeader>
          <CardContent>
            <ul className="grid list-disc gap-2 pl-5 text-sm leading-relaxed text-muted md:grid-cols-2">
              <li>Messages are analyzed in memory. Only metadata (score, findings, versions) is stored.</li>
              <li>With AI explanation enabled, a copy with long numbers and e-mail addresses masked is sent to Groq for processing under Groq&apos;s terms.</li>
              <li>URLs are analyzed offline and never visited. Only scheme + host are stored, not paths or query strings.</li>
              <li>Never submit real passwords, OTPs, PINs, card numbers or API keys — SentinelAI never needs them.</li>
              <li>Scan records can be deleted any time from Scan history and expire automatically.</li>
              <li>Application logs never contain submitted content.</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

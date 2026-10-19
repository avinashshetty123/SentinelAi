"use client";

import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, GraduationCap, RotateCcw, ShieldAlert, ShieldCheck, Trophy, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { RiskBadge, RiskScore } from "@/components/risk";
import { HighlightedText } from "@/components/scan/visuals";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Round {
  from: string;
  channel: "SMS" | "WhatsApp" | "E-mail";
  text: string;
  scam: boolean;
  lesson: string;
}

// Synthetic training messages (a mix of scams and genuine messages).
const ROUNDS: Round[] = [
  { from: "VM-HDFCBK", channel: "SMS", scam: true, text: "Dear Customer, your HDFC account will be blocked today due to pending KYC. Update now at http://hdfc-kyc-update.xyz/verify and share the OTP received to avoid suspension.", lesson: "Banks never ask for OTPs or send KYC links that aren't on their own domain." },
  { from: "Swiggy", channel: "SMS", scam: false, text: "Your Swiggy order #4821 from Meghana Foods is out for delivery. Track it in the Swiggy app. Enjoy your meal!", lesson: "No request, no link to log in, no pressure — just information you expected." },
  { from: "+91 98xxx 21044", channel: "WhatsApp", scam: true, text: "Hello! I am Priya from HR. We are hiring part-time. Like YouTube videos and earn Rs 3000 per day, no experience needed. Pay a small refundable registration fee of Rs 500 to start. Contact me only on Telegram.", lesson: "Real jobs never charge you to join. 'Easy money + fee + move to Telegram' is the task-scam recipe." },
  { from: "Amazon.in", channel: "E-mail", scam: false, text: "Your package with 2 items has been delivered. If you didn't receive it, visit Your Orders on amazon.in to get help.", lesson: "Points you to the official site you already use, asks for nothing sensitive." },
  { from: "IT Dept", channel: "SMS", scam: true, text: "Income Tax Department: You are eligible for a refund of Rs 15,490. Claim your refund within 24 hours by submitting your card details at http://203.0.113.80/refund", lesson: "Government refunds don't arrive by SMS link on a raw IP address and never need card details." },
  { from: "Mom", channel: "WhatsApp", scam: false, text: "Reached home safely. Don't forget to call your grandmother tomorrow, it's her birthday!", lesson: "Ordinary personal message — urgency-free and asks for nothing." },
  { from: "Microsoft Support", channel: "E-mail", scam: true, text: "Microsoft Security Team: we detected a virus on your computer. Install AnyDesk now so our technician can fix it remotely, and do not turn off your PC or tell anyone.", lesson: "Remote-access requests + secrecy = tech-support scam. Microsoft never cold-contacts you like this." },
  { from: "Delhivery", channel: "SMS", scam: true, text: "Your parcel is on hold due to an incomplete address. Pay the redelivery fee of Rs 25 within 2 hours at bit.ly/dlv-redeliver or it will be returned.", lesson: "Tiny 'redelivery fees' via shortened links are a classic card-harvesting trick." },
];

const BEST_KEY = "sentinel.lab.best";

export default function AwarenessLabPage() {
  const [index, setIndex] = useState(0);
  const [score, setScore] = useState(0);
  const [guess, setGuess] = useState<boolean | null>(null);
  const [best, setBest] = useState<number | null>(null);
  const analyze = useMutation({ mutationFn: api.scanMessage });
  const done = index >= ROUNDS.length;
  const round = ROUNDS[Math.min(index, ROUNDS.length - 1)];

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(BEST_KEY);
      if (saved) setBest(Number(saved)); // eslint-disable-line react-hooks/set-state-in-effect
    } catch {
      /* storage unavailable */
    }
  }, []);

  const answer = (isScam: boolean) => {
    setGuess(isScam);
    if (isScam === round.scam) setScore((s) => s + 1);
    analyze.mutate({ text: round.text, content_type: "auto", use_llm: false, persist: false });
  };

  const next = () => {
    const nextIndex = index + 1;
    setIndex(nextIndex);
    setGuess(null);
    analyze.reset();
    if (nextIndex >= ROUNDS.length) {
      try {
        const prev = Number(window.localStorage.getItem(BEST_KEY) ?? 0);
        if (score > prev) window.localStorage.setItem(BEST_KEY, String(score));
        setBest(Math.max(prev, score));
      } catch {
        /* storage unavailable */
      }
    }
  };

  const restart = () => {
    setIndex(0);
    setScore(0);
    setGuess(null);
    analyze.reset();
  };

  const correct = guess !== null && guess === round.scam;

  return (
    <>
      <PageHeader
        title="Scam Spotter — awareness lab"
        description="Most fraud succeeds because people act before they think. Guess whether each message is a scam, then see exactly which clues SentinelAI's engine picked up."
      />
      {done ? (
        <Card className="mx-auto max-w-xl">
          <CardContent className="flex flex-col items-center gap-4 py-10 text-center">
            <Trophy className="size-12 text-risk-medium" aria-hidden />
            <p className="text-3xl font-semibold">{score} / {ROUNDS.length}</p>
            <p className="text-sm text-muted">
              {score === ROUNDS.length ? "Perfect — you'd be hard to fool." : score >= 6 ? "Sharp eyes! Review the ones you missed." : "Scammers rely on speed. Slow down and look for the clues highlighted in each round."}
            </p>
            {best !== null && <Badge tone="accent">Your best: {best} / {ROUNDS.length}</Badge>}
            <Button onClick={restart}><RotateCcw aria-hidden /> Play again</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="mx-auto flex max-w-3xl flex-col gap-5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted">Round {index + 1} of {ROUNDS.length}</span>
            <div className="flex h-2 w-40 overflow-hidden rounded-full bg-surface-3" aria-hidden>
              <div className="bg-accent transition-all" style={{ width: `${(index / ROUNDS.length) * 100}%` }} />
            </div>
            <span className="flex items-center gap-1 text-muted"><GraduationCap className="size-4" aria-hidden /> Score {score}</span>
          </div>

          <Card>
            <CardContent className="py-6">
              <div className="mb-3 flex items-center gap-2 text-xs text-muted">
                <span className="flex size-8 items-center justify-center rounded-full bg-surface-3 font-semibold text-fg">{round.from.slice(0, 1)}</span>
                <span className="font-medium text-fg">{round.from}</span>
                <Badge>{round.channel}</Badge>
              </div>
              {analyze.data?.analyzed_text && guess !== null ? (
                <HighlightedText text={analyze.data.analyzed_text} highlights={analyze.data.highlights} />
              ) : (
                <p className="max-w-[85%] rounded-2xl rounded-tl-sm bg-surface-3 px-4 py-3 text-sm leading-relaxed">{round.text}</p>
              )}
            </CardContent>
          </Card>

          {guess === null ? (
            <div className="grid grid-cols-2 gap-3">
              <Button size="lg" variant="danger" onClick={() => answer(true)}><ShieldAlert aria-hidden /> It&apos;s a scam</Button>
              <Button size="lg" variant="secondary" onClick={() => answer(false)}><ShieldCheck aria-hidden /> Looks legit</Button>
            </div>
          ) : (
            <Card className={cn(correct ? "border-risk-low/50" : "border-risk-critical/50")}>
              <CardContent className="flex flex-col gap-4 py-5">
                <div className="flex items-center gap-2 text-lg font-semibold">
                  {correct ? <CheckCircle2 className="size-6 text-green-400" aria-hidden /> : <XCircle className="size-6 text-rose-400" aria-hidden />}
                  {correct ? "Correct!" : "Not quite."} This message is {round.scam ? "a scam" : "legitimate"}.
                </div>
                <p className="text-sm text-muted">{round.lesson}</p>
                {analyze.isPending && <LoadingState label="Asking the engine…" />}
                {analyze.isError && <ErrorState error={analyze.error} />}
                {analyze.data && (
                  <div className="flex items-center gap-4 rounded-lg border border-border bg-surface-2 p-3">
                    <RiskScore score={analyze.data.risk_score} level={analyze.data.risk_level} size="sm" />
                    <div className="flex flex-col gap-1 text-xs">
                      <span className="flex items-center gap-2">SentinelAI verdict: <RiskBadge level={analyze.data.risk_level} /></span>
                      <span className="text-muted">
                        {analyze.data.findings.filter((f) => f.points > 0).slice(0, 3).map((f) => f.title).join(" · ") || "No risk indicators found."}
                      </span>
                    </div>
                  </div>
                )}
                <Button className="self-end" onClick={next}>{index + 1 === ROUNDS.length ? "See results" : "Next message →"}</Button>
              </CardContent>
            </Card>
          )}
          <p className="text-center text-[11px] text-subtle">All messages are synthetic. Practice rounds are analyzed but never saved.</p>
        </div>
      )}
    </>
  );
}

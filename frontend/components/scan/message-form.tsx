"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ScanSearch } from "lucide-react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { FieldError, Label, Select, Switch, Textarea } from "@/components/ui/form";
import type { ContentType } from "@/types/api";

export const MAX_MESSAGE_CHARS = 10_000;

export const CONTENT_TYPES: { value: ContentType; label: string }[] = [
  { value: "auto", label: "Auto-detect" },
  { value: "sms", label: "SMS" },
  { value: "email", label: "Email (subject + body)" },
  { value: "job_offer", label: "Job offer" },
  { value: "payment_request", label: "Payment request" },
  { value: "account_verification", label: "Account verification" },
  { value: "delivery", label: "Delivery notification" },
  { value: "prize", label: "Prize / reward" },
  { value: "chat", label: "Chat message" },
  { value: "general", label: "General text" },
];

export const messageSchema = z.object({
  text: z
    .string()
    .trim()
    .min(1, "Paste the message you want to analyze.")
    .max(MAX_MESSAGE_CHARS, `Messages are limited to ${MAX_MESSAGE_CHARS.toLocaleString()} characters.`),
  content_type: z.enum(CONTENT_TYPES.map((c) => c.value) as [ContentType, ...ContentType[]]),
  use_llm: z.boolean(),
});

export type MessageFormValues = z.infer<typeof messageSchema>;

export const SAMPLE_MESSAGES: { label: string; text: string; content_type: ContentType }[] = [
  {
    label: "Payment scam",
    content_type: "payment_request",
    text: "[SYNTHETIC] URGENT: Your electricity connection will be disconnected tonight. Pay the pending bill of Rs 1,250 immediately at http://203.0.113.50/pay-now and share the OTP to confirm. Do not contact the office.",
  },
  {
    label: "Job offer",
    content_type: "job_offer",
    text: "[SYNTHETIC] Congratulations! You are selected for a part-time work from home job. Earn $300 per day liking YouTube videos. No experience needed. Pay a refundable registration fee of $25 to start. Contact us only on Telegram.",
  },
  {
    label: "Account phishing",
    content_type: "account_verification",
    text: "[SYNTHETIC] Dear Customer, PayPal Security Team detected unusual activity. Your account will be suspended within 24 hours. Verify your account at https://paypa1-secure-login.xyz/verify and enter your password.",
  },
  {
    label: "Ordinary message",
    content_type: "sms",
    text: "Hi! Your table for 4 at 7:30pm on Friday is confirmed. Reply C to cancel. See you soon.",
  },
];

export function MessageForm({
  onSubmit,
  pending,
  llmAvailable,
}: {
  onSubmit: (values: MessageFormValues) => void;
  pending: boolean;
  llmAvailable: boolean | null;
}) {
  const {
    register,
    handleSubmit,
    control,
    setValue,
    formState: { errors },
  } = useForm<MessageFormValues>({
    resolver: zodResolver(messageSchema),
    defaultValues: { text: "", content_type: "auto", use_llm: true },
  });
  const length = useWatch({ control, name: "text" })?.length ?? 0;
  const useLlm = useWatch({ control, name: "use_llm" });

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between">
          <Label htmlFor="message-text">Message</Label>
          <span className={length > MAX_MESSAGE_CHARS ? "text-xs text-risk-critical" : "text-xs text-subtle"}>
            {length.toLocaleString()} / {MAX_MESSAGE_CHARS.toLocaleString()}
          </span>
        </div>
        <Textarea
          id="message-text"
          rows={8}
          placeholder="Paste a suspicious SMS, email, job offer or chat message. Do not include real passwords, OTPs or card numbers."
          aria-invalid={errors.text ? "true" : "false"}
          aria-describedby={errors.text ? "message-text-error" : undefined}
          {...register("text")}
        />
        <FieldError id="message-text-error" message={errors.text?.message} />
      </div>

      <div className="flex flex-wrap gap-2" aria-label="Load a synthetic example">
        <span className="self-center text-xs text-subtle">Synthetic examples:</span>
        {SAMPLE_MESSAGES.map((s) => (
          <Button
            key={s.label}
            variant="outline"
            size="sm"
            onClick={() => {
              setValue("text", s.text, { shouldValidate: true });
              setValue("content_type", s.content_type);
            }}
          >
            {s.label}
          </Button>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="content-type">Content type</Label>
          <Select id="content-type" {...register("content_type")}>
            {CONTENT_TYPES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface-2 px-3 py-2">
          <div className="flex flex-col">
            <span className="text-sm">AI explanation (Groq)</span>
            <span className="text-[11px] text-subtle">
              {llmAvailable === false ? "Not available on this server" : "Sends a minimized copy to Groq"}
            </span>
          </div>
          <Controller
            control={control}
            name="use_llm"
            render={({ field }) => (
              <Switch checked={field.value} onCheckedChange={field.onChange} label="Request AI explanation" />
            )}
          />
        </div>
      </div>

      <p className="text-[11px] leading-relaxed text-subtle">
        Privacy: the message text is analyzed in memory and is not stored.{" "}
        {useLlm
          ? "With AI explanation on, a copy with long numbers and e-mail addresses masked is sent to the configured Groq model for processing."
          : "With AI explanation off, nothing is sent to any external provider."}
      </p>

      <Button type="submit" size="lg" loading={pending} className="self-start">
        <ScanSearch aria-hidden /> Analyze message
      </Button>
    </form>
  );
}

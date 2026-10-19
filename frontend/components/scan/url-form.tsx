"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Link2 } from "lucide-react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { FieldError, Input, Label, Switch } from "@/components/ui/form";

export const urlSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, "Enter a URL to analyze.")
    .max(2048, "URLs are limited to 2048 characters.")
    .refine((v) => !/^\s*(javascript|data|vbscript|file|blob):/i.test(v), "Only http(s) URLs can be analyzed.")
    .refine((v) => !/\s/.test(v), "URLs cannot contain spaces."),
  use_llm: z.boolean(),
});

export type UrlFormValues = z.infer<typeof urlSchema>;

export const SAMPLE_URLS = [
  "http://paypa1-secure-login.xyz/verify",
  "https://paypal.com.account-check.example/login",
  "http://user@203.0.113.7:8080/update.apk",
  "https://xn--pypal-4ve.com/",
  "https://bit.ly/3SyNtH",
  "https://www.wikipedia.org/",
];

export function UrlForm({ onSubmit, pending }: { onSubmit: (values: UrlFormValues) => void; pending: boolean }) {
  const {
    register,
    handleSubmit,
    control,
    setValue,
    formState: { errors },
  } = useForm<UrlFormValues>({ resolver: zodResolver(urlSchema), defaultValues: { url: "", use_llm: false } });

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="url-input">URL</Label>
        <Input
          id="url-input"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://example.com/login"
          aria-invalid={errors.url ? "true" : "false"}
          aria-describedby={errors.url ? "url-error" : undefined}
          className="font-mono"
          {...register("url")}
        />
        <FieldError id="url-error" message={errors.url?.message} />
      </div>
      <div className="flex flex-wrap gap-2">
        <span className="self-center text-xs text-subtle">Synthetic examples:</span>
        {SAMPLE_URLS.map((u) => (
          <Button key={u} variant="outline" size="sm" className="font-mono" onClick={() => setValue("url", u, { shouldValidate: true })}>
            {u.replace(/^https?:\/\//, "").slice(0, 28)}
          </Button>
        ))}
      </div>
      <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface-2 px-3 py-2 sm:max-w-md">
        <div className="flex flex-col">
          <span className="text-sm">AI explanation of features</span>
          <span className="text-[11px] text-subtle">Sends the URL without its query string and the extracted features</span>
        </div>
        <Controller
          control={control}
          name="use_llm"
          render={({ field }) => <Switch checked={field.value} onCheckedChange={field.onChange} label="Request AI explanation" />}
        />
      </div>
      <Button type="submit" size="lg" loading={pending} className="self-start">
        <Link2 aria-hidden /> Analyze URL
      </Button>
    </form>
  );
}

"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { FieldError, Label, Select, Textarea } from "@/components/ui/form";
import type { IncidentStatus, RiskLevel } from "@/types/api";

export const STATUSES: IncidentStatus[] = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];
const CLOSED: IncidentStatus[] = ["RESOLVED", "FALSE_POSITIVE"];

export const statusSchema = z
  .object({
    status: z.enum(["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    resolution_notes: z.string().max(4000, "Resolution notes are limited to 4000 characters."),
  })
  .superRefine((value, ctx) => {
    if (CLOSED.includes(value.status) && !value.resolution_notes.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["resolution_notes"],
        message: "Resolution notes are required to resolve or close as false positive.",
      });
    }
  });

export type StatusFormValues = z.infer<typeof statusSchema>;

export function IncidentStatusForm({
  initial,
  onSubmit,
  pending,
}: {
  initial: { status: IncidentStatus; severity: RiskLevel; resolution_notes: string | null };
  onSubmit: (values: StatusFormValues) => void;
  pending: boolean;
}) {
  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isDirty },
  } = useForm<StatusFormValues>({
    resolver: zodResolver(statusSchema),
    defaultValues: { status: initial.status, severity: initial.severity, resolution_notes: initial.resolution_notes ?? "" },
  });
  const status = useWatch({ control, name: "status" });
  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor="inc-status">Status</Label>
          <Select id="inc-status" {...register("status")}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor="inc-severity">Severity</Label>
          <Select id="inc-severity" {...register("severity")}>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
      </div>
      {(CLOSED.includes(status) || initial.resolution_notes) && (
        <div className="flex flex-col gap-1">
          <Label htmlFor="inc-resolution">Resolution notes</Label>
          <Textarea
            id="inc-resolution"
            rows={3}
            className="min-h-20"
            placeholder="What was found and what was done?"
            aria-invalid={errors.resolution_notes ? "true" : "false"}
            aria-describedby={errors.resolution_notes ? "inc-resolution-error" : undefined}
            {...register("resolution_notes")}
          />
          <FieldError id="inc-resolution-error" message={errors.resolution_notes?.message} />
        </div>
      )}
      <Button type="submit" size="sm" className="self-start" loading={pending} disabled={!isDirty}>
        Save changes
      </Button>
    </form>
  );
}

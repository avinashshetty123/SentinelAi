"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { FieldError, Input, Label, Select, Textarea } from "@/components/ui/form";

const schema = z.object({
  title: z.string().trim().min(3, "Title must be at least 3 characters.").max(200),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  description: z.string().max(4000),
  evidence_summary: z.string().max(4000),
});

export type CreateIncidentValues = z.infer<typeof schema>;

export function CreateIncidentForm({
  onSubmit,
  onCancel,
  pending,
  linkedEventId,
}: {
  onSubmit: (values: CreateIncidentValues) => void;
  onCancel: () => void;
  pending: boolean;
  linkedEventId?: string | null;
}) {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<CreateIncidentValues>({
    resolver: zodResolver(schema),
    defaultValues: { title: "", severity: "MEDIUM", description: "", evidence_summary: "" },
  });
  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <Label htmlFor="new-title">Title</Label>
        <Input
          id="new-title"
          aria-invalid={errors.title ? "true" : "false"}
          aria-describedby={errors.title ? "new-title-error" : undefined}
          {...register("title")}
        />
        <FieldError id="new-title-error" message={errors.title?.message} />
      </div>
      <div className="flex flex-col gap-1 sm:max-w-xs">
        <Label htmlFor="new-severity">Severity</Label>
        <Select id="new-severity" {...register("severity")}>
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor="new-description">Description</Label>
        <Textarea id="new-description" rows={3} className="min-h-20" {...register("description")} />
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor="new-evidence">Evidence summary</Label>
        <Textarea id="new-evidence" rows={3} className="min-h-20" {...register("evidence_summary")} />
      </div>
      {linkedEventId && <p className="text-xs text-muted">Event {linkedEventId.slice(0, 8)} will be linked to this incident.</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" loading={pending}>
          Create incident
        </Button>
        <Button variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

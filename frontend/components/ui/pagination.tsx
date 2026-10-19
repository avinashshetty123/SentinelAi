import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-3 border-t border-border px-4 py-3">
      <p className="text-xs text-muted">
        {total === 0 ? "No results" : `Page ${page} of ${pages} · ${total} total`}
      </p>
      <div className="flex gap-2">
        <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          <ChevronLeft aria-hidden /> Previous
        </Button>
        <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => onPageChange(page + 1)}>
          Next <ChevronRight aria-hidden />
        </Button>
      </div>
    </nav>
  );
}

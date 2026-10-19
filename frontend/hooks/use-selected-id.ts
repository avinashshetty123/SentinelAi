"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Detail selection kept in the `?id=` query param so views are linkable. Must render inside <Suspense>. */
export function useSelectedId(): [string | null, (id: string | null) => void] {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const raw = params.get("id");
  const selected = raw && UUID_RE.test(raw) ? raw : null;
  const setSelected = useCallback(
    (id: string | null) => {
      const next = new URLSearchParams(params.toString());
      if (id) next.set("id", id);
      else next.delete("id");
      const qs = next.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [params, pathname, router],
  );
  return [selected, setSelected];
}

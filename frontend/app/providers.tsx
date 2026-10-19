"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { EventStreamProvider } from "@/hooks/use-event-stream";
import { ApiError } from "@/lib/api";

let browserQueryClient: QueryClient | undefined;

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        retry: (count, error) => {
          // Do not retry client errors (auth, validation, not found, rate limit).
          if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
          return count < 2;
        },
      },
    },
  });
}

function getQueryClient() {
  if (typeof window === "undefined") return makeQueryClient();
  browserQueryClient ??= makeQueryClient();
  return browserQueryClient;
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={getQueryClient()}>
      <EventStreamProvider>{children}</EventStreamProvider>
    </QueryClientProvider>
  );
}

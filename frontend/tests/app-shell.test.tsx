import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AppShell, NAV_ITEMS } from "@/components/shell/app-shell";

vi.mock("next/navigation", () => ({ usePathname: () => "/incidents" }));
vi.mock("next/link", () => ({
  default: ({ href, children, onClick, ...rest }: { href: string; children: React.ReactNode; onClick?: () => void }) => (
    <a href={href} onClick={(e) => { e.preventDefault(); onClick?.(); }} {...rest}>
      {children}
    </a>
  ),
}));
vi.mock("@/components/shell/auth-banner", () => ({ AuthBanner: () => null }));
vi.mock("@/components/shell/connection-status", () => ({ ConnectionStatus: () => <span>Live</span> }));

describe("AppShell navigation", () => {
  it("marks the current page and lists every section", () => {
    render(<AppShell><p>content</p></AppShell>);
    const nav = screen.getAllByRole("navigation", { name: "Main navigation" })[0];
    expect(within(nav).getAllByRole("link")).toHaveLength(NAV_ITEMS.length);
    expect(within(nav).getByRole("link", { name: "Incidents" })).toHaveAttribute("aria-current", "page");
  });

  it("opens and closes the mobile drawer (button and Escape)", async () => {
    render(<AppShell><p>content</p></AppShell>);
    const toggle = screen.getByRole("button", { name: "Open navigation" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(toggle);
    const dialog = screen.getByRole("dialog", { name: "Navigation" });
    expect(within(dialog).getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await userEvent.click(toggle);
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("link", { name: "Dashboard" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("provides a skip link to main content", () => {
    render(<AppShell><p>content</p></AppShell>);
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
  });
});

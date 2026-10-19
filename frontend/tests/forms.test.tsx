import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IncidentStatusForm } from "@/components/incidents/status-form";
import { MAX_MESSAGE_CHARS, MessageForm } from "@/components/scan/message-form";
import { UrlForm } from "@/components/scan/url-form";

describe("MessageForm validation", () => {
  it("rejects an empty message and does not submit", async () => {
    const onSubmit = vi.fn();
    render(<MessageForm onSubmit={onSubmit} pending={false} llmAvailable />);
    await userEvent.click(screen.getByRole("button", { name: /analyze message/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/paste the message/i);
    expect(screen.getByLabelText("Message")).toHaveAttribute("aria-invalid", "true");
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("rejects messages over the length limit", async () => {
    const onSubmit = vi.fn();
    render(<MessageForm onSubmit={onSubmit} pending={false} llmAvailable />);
    const box = screen.getByLabelText("Message");
    await userEvent.click(box);
    await userEvent.paste("a".repeat(MAX_MESSAGE_CHARS + 1));
    await userEvent.click(screen.getByRole("button", { name: /analyze message/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/limited/i);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("submits valid input including the AI toggle and content type", async () => {
    const onSubmit = vi.fn();
    render(<MessageForm onSubmit={onSubmit} pending={false} llmAvailable />);
    await userEvent.type(screen.getByLabelText("Message"), "Please share your OTP now");
    await userEvent.selectOptions(screen.getByLabelText("Content type"), "sms");
    await userEvent.click(screen.getByRole("switch", { name: /ai explanation/i }));
    await userEvent.click(screen.getByRole("button", { name: /analyze message/i }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(onSubmit.mock.calls[0][0]).toEqual({ text: "Please share your OTP now", content_type: "sms", use_llm: false });
  });

  it("explains what is sent to the LLM provider", async () => {
    render(<MessageForm onSubmit={vi.fn()} pending={false} llmAvailable />);
    expect(screen.getByText(/sent to the configured Groq model/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("switch", { name: /ai explanation/i }));
    expect(screen.getByText(/nothing is sent to any external provider/i)).toBeInTheDocument();
  });

  it("loads a synthetic example", async () => {
    render(<MessageForm onSubmit={vi.fn()} pending={false} llmAvailable={false} />);
    await userEvent.click(screen.getByRole("button", { name: "Job offer" }));
    expect((screen.getByLabelText("Message") as HTMLTextAreaElement).value).toMatch(/SYNTHETIC/);
    expect(screen.getByText(/not available on this server/i)).toBeInTheDocument();
  });
});

describe("UrlForm validation", () => {
  it.each(["javascript:alert(1)", "data:text/html,x", "http://exa mple.com"])("rejects %s", async (value) => {
    const onSubmit = vi.fn();
    render(<UrlForm onSubmit={onSubmit} pending={false} />);
    await userEvent.type(screen.getByLabelText("URL"), value);
    await userEvent.click(screen.getByRole("button", { name: /analyze url/i }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("accepts an http(s) URL", async () => {
    const onSubmit = vi.fn();
    render(<UrlForm onSubmit={onSubmit} pending={false} />);
    await userEvent.type(screen.getByLabelText("URL"), "https://paypa1.com/login");
    await userEvent.click(screen.getByRole("button", { name: /analyze url/i }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ url: "https://paypa1.com/login", use_llm: false }, expect.anything()));
  });
});

describe("IncidentStatusForm", () => {
  const initial = { status: "INVESTIGATING" as const, severity: "HIGH" as const, resolution_notes: null };

  it("requires resolution notes when resolving", async () => {
    const onSubmit = vi.fn();
    render(<IncidentStatusForm initial={initial} onSubmit={onSubmit} pending={false} />);
    await userEvent.selectOptions(screen.getByLabelText("Status"), "RESOLVED");
    await userEvent.click(screen.getByRole("button", { name: /save changes/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/resolution notes are required/i);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("submits a resolution with notes", async () => {
    const onSubmit = vi.fn();
    render(<IncidentStatusForm initial={initial} onSubmit={onSubmit} pending={false} />);
    await userEvent.selectOptions(screen.getByLabelText("Status"), "RESOLVED");
    await userEvent.type(screen.getByLabelText("Resolution notes"), "Sender blocked");
    await userEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ status: "RESOLVED", resolution_notes: "Sender blocked" });
  });

  it("disables saving until something changes", () => {
    render(<IncidentStatusForm initial={initial} onSubmit={vi.fn()} pending={false} />);
    expect(screen.getByRole("button", { name: /save changes/i })).toBeDisabled();
  });
});

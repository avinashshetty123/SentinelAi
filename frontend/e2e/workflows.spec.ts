import { expect, test } from "@playwright/test";

test.describe("core workflows", () => {
  test("message → deterministic analysis → risk score → results", async ({ page }) => {
    await page.goto("/analyze");
    await page.getByRole("button", { name: "Payment scam" }).click();
    await page.getByRole("button", { name: /analyze message/i }).click();
    await expect(page.getByRole("img", { name: /risk score \d+ out of 100/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /detected indicators/i })).toBeVisible();
    await expect(page.getByText("Request for a one-time code")).toBeVisible();
    await expect(page.getByRole("heading", { name: /recommended actions/i })).toBeVisible();
    // Either a validated AI explanation or an explicit "unavailable" notice — never silent.
    await expect(page.getByText(/AI explanation/).first()).toBeVisible();
  });

  test("URL → safe offline checks → findings", async ({ page }) => {
    await page.goto("/urls");
    await page.getByLabel("URL").fill("http://paypa1-secure-login.xyz/verify");
    await page.getByRole("button", { name: /analyze url/i }).click();
    await expect(page.getByText("Lookalike of 'paypal'")).toBeVisible();
    await expect(page.getByText(/the URL was not visited/i).first()).toBeVisible();
    await expect(page.getByText("Not configured")).toBeVisible();
  });

  test("demo event → persisted → WebSocket → displayed live", async ({ page }) => {
    await page.goto("/events");
    await expect(page.getByRole("button", { name: /event stream: live/i })).toBeVisible();
    const before = await page.getByRole("list", { name: "Security events" }).getByRole("listitem").count().catch(() => 0);
    await page.getByLabel("Event type").selectOption("suspicious_login");
    await page.getByRole("button", { name: "Generate event" }).click();
    // The new row arrives through the WebSocket-triggered refresh, flagged as new, without a reload.
    const list = page.getByRole("list", { name: "Security events" });
    await expect(list.getByText("new", { exact: true }).first()).toBeVisible();
    await expect.poll(async () => list.getByRole("listitem").count()).toBeGreaterThan(before === 20 ? 19 : before);
    await expect(list.getByText(/\[SIMULATED\] Sign-in/).first()).toBeVisible();
  });

  test("incident → note → resolve → audit history", async ({ page }) => {
    const title = `E2E incident ${Date.now()}`;
    await page.goto("/incidents");
    await page.getByRole("button", { name: "New incident" }).click();
    await page.getByLabel("Title").fill(title);
    await page.getByLabel("Severity").first().selectOption("HIGH");
    await page.getByRole("button", { name: "Create incident" }).click();
    await expect(page.getByRole("heading", { name: title })).toBeVisible();

    await page.getByLabel("Add analyst note").fill("Blocked the sender domain.");
    await page.getByRole("button", { name: "Add note" }).click();
    await expect(page.getByText("Blocked the sender domain.").first()).toBeVisible();

    await page.getByLabel("Status", { exact: true }).selectOption("RESOLVED");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText(/resolution notes are required/i)).toBeVisible();
    await page.getByLabel("Resolution notes").fill("Users warned; domain blocked.");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Status INVESTIGATING → RESOLVED").or(page.getByText("Status OPEN → RESOLVED"))).toBeVisible();

    await page.getByText(/audit trail/i).click();
    await expect(page.getByText("incident.created")).toBeVisible();
    await expect(page.getByText("incident.note_added")).toBeVisible();
  });
});

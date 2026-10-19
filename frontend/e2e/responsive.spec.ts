import { expect, test } from "@playwright/test";

test("mobile navigation drawer works and pages do not overflow horizontally", async ({ page }) => {
  await page.goto("/dashboard");
  await page.getByRole("button", { name: "Open navigation" }).click();
  const drawer = page.getByRole("dialog", { name: "Navigation" });
  await drawer.getByRole("link", { name: "Message analyzer" }).click();
  await expect(page).toHaveURL(/\/analyze$/);
  await expect(drawer).toBeHidden();
  for (const path of ["/", "/dashboard", "/analyze", "/incidents", "/events", "/replay"]) {
    await page.goto(path);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `${path} overflows horizontally`).toBeLessThanOrEqual(1);
  }
});

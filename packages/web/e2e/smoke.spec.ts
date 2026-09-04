import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const VALID = {
  message: 'Sign in to example.com\nnonce: 0123456789abcdef',
  publicKey: '035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA',
  signature:
    '30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
};

test('verifies and rejects a message with no page errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  await page.goto('./');
  await expect(page.getByRole('heading', { name: 'XRPL Message Verify' })).toBeVisible();

  await page.fill('#msg-text', VALID.message);
  await page.fill('#msg-pubkey', VALID.publicKey);
  await page.fill('#msg-sig', VALID.signature);
  await page.fill('#msg-address', VALID.address);
  await page.click('#form-message button[type=submit]');
  await expect(page.locator('#result-message .verdict')).toHaveAttribute('data-valid', 'true');
  await expect(page.locator('#result-message')).toContainText(VALID.address);

  await page.fill('#msg-text', VALID.message + '!');
  await page.click('#form-message button[type=submit]');
  await expect(page.locator('#result-message .verdict')).toHaveAttribute('data-valid', 'false');
  await expect(page.locator('#result-message')).toContainText('bad_signature');

  expect(errors).toEqual([]);
});

test('verifies a SignIn blob from the fixtures', async ({ page }) => {
  const vectors = JSON.parse(
    readFileSync(new URL('../../../fixtures/vectors.json', import.meta.url), 'utf8'),
  ).vectors as Array<{
    kind: string;
    blobHex?: string;
    expect: { valid: boolean };
    options?: unknown;
  }>;
  const v = vectors.find((x) => x.kind === 'signin' && x.expect.valid && !x.options);
  test.skip(!v, 'no valid signin vector');
  await page.goto('./');
  await page.getByRole('tab', { name: 'Xaman SignIn blob' }).click();
  await page.fill('#si-blob', v!.blobHex!);
  await page.click('#form-signin button[type=submit]');
  await expect(page.locator('#result-signin .verdict')).toHaveAttribute('data-valid', 'true');
  await expect(page.locator('#result-signin')).toContainText('SignIn');
});

import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const VALID = {
  message: 'Sign in to example.com\nnonce: 0123456789abcdef',
  publicKey: '035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA',
  signature:
    '30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
};

let errors: string[] = [];
test.beforeEach(({ page }) => {
  errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
});
test.afterEach(() => {
  expect(errors).toEqual([]);
});

test('verifies and rejects a message with no page errors', async ({ page }) => {
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
  expect(v).toBeDefined();
  await page.goto('./');
  await page.getByRole('tab', { name: 'Xaman SignIn blob' }).click();
  await page.fill('#si-blob', v!.blobHex!);
  await page.click('#form-signin button[type=submit]');
  await expect(page.locator('#result-signin .verdict')).toHaveAttribute('data-valid', 'true');
  await expect(page.locator('#result-signin')).toContainText('SignIn');
});

test('creates a request link that opens on the sign step', async ({ page }) => {
  await page.goto('./');
  await page.getByRole('tab', { name: 'Prove ownership' }).click();
  await page.fill('#rq-domain', 'example.com');
  await page.fill('#rq-address', 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA');
  await page.fill('#rq-statement', 'Ownership check');
  await page.click('#form-request button[type=submit]');
  const text = await page.textContent('#request-text');
  expect(text).toContain('example.com wants you to prove control of XRP Ledger account:');
  expect(text).toContain('rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA');
  const link = await page.inputValue('#request-link');
  expect(link).toContain('#sign?c=');

  await page.goto(link);
  await expect(page.getByRole('tab', { name: 'Prove ownership' })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.locator('#request-block')).toBeHidden();
  expect(await page.inputValue('#sign-text')).toBe(text);
  await expect(page.locator('#sign-gem')).toBeVisible();
});

test('a proof link verifies on load and shows the request details', async ({ page }) => {
  const vectors = JSON.parse(
    readFileSync(new URL('../../../fixtures/vectors.json', import.meta.url), 'utf8'),
  ).vectors as Array<{
    kind: string;
    message?: string;
    publicKey?: string;
    signature?: string;
    expect: { valid: boolean; derivedAddress?: string };
    account?: unknown;
    address?: string;
  }>;
  const v = vectors.find(
    (x) =>
      x.kind === 'message' &&
      x.expect.valid &&
      !x.account &&
      x.message?.includes('wants you to prove control of XRP Ledger account'),
  );
  expect(v).toBeDefined();
  const proof = {
    message: v!.message,
    publicKey: v!.publicKey,
    signature: v!.signature,
    address: v!.address ?? v!.expect.derivedAddress,
  };
  const b64 = Buffer.from(JSON.stringify(proof), 'utf8').toString('base64url');
  await page.goto(`./#verify?p=${b64}`);
  await expect(page.locator('#result-message .verdict')).toHaveAttribute('data-valid', 'true');
  await expect(page.locator('#result-message')).toContainText('Ownership request');
  await expect(page.locator('#result-message')).toContainText('Nonce');
});

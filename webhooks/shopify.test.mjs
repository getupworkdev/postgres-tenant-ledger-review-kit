import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verifyShopifyHmac, toLedgerEvent } from './shopify.mjs';

const secret = 'test_secret';
const raw = Buffer.from('{"inventory_item_id": 42,  "location_id": 7, "available": 12}');
const sign = (body) => createHmac('sha256', secret).update(body).digest('base64');

test('accepts the HMAC of the raw body', () => {
  assert.equal(verifyShopifyHmac(raw, sign(raw), secret), true);
});

test('rejects when the body was re-serialised before checking', () => {
  const reserialised = Buffer.from(JSON.stringify(JSON.parse(raw.toString())));
  assert.equal(verifyShopifyHmac(reserialised, sign(raw), secret), false);
});

test('rejects a tampered body, a wrong secret, and missing headers', () => {
  assert.equal(verifyShopifyHmac(Buffer.from(raw.toString().replace('12', '99')), sign(raw), secret), false);
  assert.equal(verifyShopifyHmac(raw, sign(raw), 'other'), false);
  assert.equal(verifyShopifyHmac(raw, undefined, secret), false);
  assert.equal(verifyShopifyHmac(raw, 'not-base64!!', secret), false);
});

test('maps an absolute level to a delta keyed by the webhook id', () => {
  const ev = toLedgerEvent({
    headers: { 'x-shopify-webhook-id': 'wh-1' },
    payload: { inventory_item_id: 42, location_id: 7, available: 12, updated_at: '2026-10-07T10:00:00Z' },
    tenantId: 't-1',
    currentOnHand: 15,
  });
  assert.equal(ev.p_qty_delta, -3);
  assert.equal(ev.p_source_event_id, 'wh-1');
});

test('no event when nothing changed, error when the webhook id is missing', () => {
  const payload = { inventory_item_id: 42, location_id: 7, available: 5 };
  assert.equal(toLedgerEvent({ headers: { 'x-shopify-webhook-id': 'x' }, payload, tenantId: 't', currentOnHand: 5 }), null);
  assert.throws(() => toLedgerEvent({ headers: {}, payload, tenantId: 't', currentOnHand: 0 }));
});

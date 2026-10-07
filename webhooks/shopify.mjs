// Shopify webhook intake: verify, then turn the delivery into a ledger event.
//
// Two rules that are easy to get wrong:
//  1. The HMAC is over the raw request bytes. Parsing JSON and re-serialising
//     it changes whitespace and key order, and the check fails (or worse, gets
//     "fixed" by disabling it).
//  2. Shopify retries and can deliver out of order. The webhook id is the
//     idempotency key, and the ledger sums deltas, so order does not matter.

import { createHmac, timingSafeEqual } from 'node:crypto';

export function verifyShopifyHmac(rawBody, headerHmac, secret) {
  if (!headerHmac || !secret) return false;
  const expected = createHmac('sha256', secret).update(rawBody).digest();
  let given;
  try {
    given = Buffer.from(headerHmac, 'base64');
  } catch {
    return false;
  }
  return given.length === expected.length && timingSafeEqual(given, expected);
}

// Map a verified delivery to the arguments of public.record_inventory_event.
// Shopify's inventory_levels/update carries the new absolute level, not a
// delta, so the delta is computed against the cached level by the caller.
export function toLedgerEvent({ headers, payload, tenantId, currentOnHand }) {
  const webhookId = headers['x-shopify-webhook-id'];
  if (!webhookId) throw new Error('missing X-Shopify-Webhook-Id');
  const delta = payload.available - currentOnHand;
  if (delta === 0) return null;
  return {
    p_tenant: tenantId,
    p_sku: String(payload.inventory_item_id),
    p_location: String(payload.location_id),
    p_qty_delta: delta,
    p_reason: 'adjust',
    p_source: 'shopify',
    p_source_event_id: webhookId,
    p_occurred_at: payload.updated_at,
  };
}

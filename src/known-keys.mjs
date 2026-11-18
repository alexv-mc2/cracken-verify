// SPDX-License-Identifier: MIT
/**
 * crAcken checkpoint verifier keys known to this release (signed-note verifier format
 * name+<4-byte key hash hex>+base64(0x01 || Ed25519 public key)). Compare with the list published on
 * cracken.tech before relying on it. Rotations add a line; old keys stay so old bundles still check.
 */
export const KNOWN_KEYS = Object.freeze([
  { verifier_key: "cracken.tech/prove-key-2026-11+30eb8ebf+AaTJP1WXQ8VIzvODrd4TXZQlR4nO+RBndZ+7eVvumLh0", origin: "cracken.tech/prove/v1", since: "2026-11-18" },
]);

// SPDX-License-Identifier: MIT
/**
 * RFC 3161 time-stamp token check on pkijs + asn1js (BSD-3-Clause, bundled; see NOTICE).
 * The anchored message is the 32-byte checkpoint Merkle root itself (`openssl ts -query -digest <root hex> -sha256`).
 *
 * Checks: token structure (CMS SignedData over TSTInfo), message imprint == root (SHA-256), CMS signature,
 * signer certificate with the critical-or-not timeStamping extended key usage, and a certificate chain at
 * genTime that ends in a root the auditor trusts: either CA certificates the auditor supplies (downloaded by
 * the auditor from the TSA, never taken from the bundle) or, by default, the pinned SHA-256 fingerprint of
 * the FreeTSA root certificate. Revocation is not checked (offline); the README says so.
 */
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { bytesEqual, sha256Hex, toArrayBuffer, toHex } from "./bytes.mjs";

/** SHA-256 of the DER of the "Free TSA Root CA" certificate (www.freetsa.org/files/cacert.pem, valid to 2041-03). */
export const FREETSA_ROOT_SHA256 = "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_DATA = "1.2.840.113549.1.7.1";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_EKU = "2.5.29.37";
const OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  if (!globalThis.crypto || !globalThis.crypto.subtle) throw new Error("webcrypto_unavailable");
  pkijs.setEngine("webcrypto", new pkijs.CryptoEngine({ name: "webcrypto", crypto: globalThis.crypto }));
  engineReady = true;
}
function fail(code) {
  throw new Error(code);
}
function stripLeadingZeros(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.subarray(i);
}

/** Accept a TimeStampResp (what `openssl ts -reply` writes) or a bare TimeStampToken; return the token DER. */
export function tokenFromResponseOrToken(der) {
  const parsed = asn1js.fromBER(toArrayBuffer(der));
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) fail("rfc3161_der_invalid");
  if (parsed.offset !== der.length) fail("rfc3161_trailing_bytes");
  const items = parsed.result.valueBlock.value;
  if (items[0] instanceof asn1js.ObjectIdentifier) return der; // ContentInfo = TimeStampToken
  if (!(items[0] instanceof asn1js.Sequence) || items.length < 2) fail("rfc3161_der_invalid");
  const status = items[0].valueBlock.value[0];
  if (!(status instanceof asn1js.Integer) || ![0, 1].includes(status.valueBlock.valueDec)) fail("rfc3161_status_not_granted");
  return new Uint8Array(items[1].valueBeforeDecodeView);
}

/**
 * Verify a token (or response) for `root`.
 * @param {Uint8Array} der
 * @param {{ root: Uint8Array, trustedCaDers?: Uint8Array[], trustedRootSha256?: string[] }} options
 * @returns {Promise<{ genTime: Date, serial: string, policy: string, tsaName: string, trustedBy: string }>}
 */
export async function verifyTimeStamp(der, options) {
  ensureEngine();
  const tokenDer = tokenFromResponseOrToken(der);
  let info;
  try { info = pkijs.ContentInfo.fromBER(toArrayBuffer(tokenDer)); } catch { fail("rfc3161_token_invalid"); }
  if (info.contentType !== OID_SIGNED_DATA) fail("rfc3161_token_invalid");
  const signed = new pkijs.SignedData({ schema: info.content });
  if (signed.encapContentInfo.eContentType !== OID_TST_INFO || !signed.encapContentInfo.eContent) fail("rfc3161_token_invalid");
  const tst = pkijs.TSTInfo.fromBER(signed.encapContentInfo.eContent.getValue());

  // 1. The token is about the checkpoint root.
  if (tst.messageImprint.hashAlgorithm.algorithmId !== OID_SHA256) fail("rfc3161_imprint_algorithm_not_sha256");
  if (!bytesEqual(new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView), options.root)) fail("rfc3161_imprint_mismatch");
  const genTime = tst.genTime;
  if (!(genTime instanceof Date) || !Number.isFinite(genTime.getTime())) fail("rfc3161_gen_time_invalid");

  // 2. Trust: auditor-supplied CA certificates, else the pinned FreeTSA root fingerprint.
  const tokenCerts = (signed.certificates ?? []).filter((c) => c instanceof pkijs.Certificate);
  const trustedCerts = [];
  let trustedBy;
  if (options.trustedCaDers && options.trustedCaDers.length > 0) {
    for (const d of options.trustedCaDers) {
      try { trustedCerts.push(pkijs.Certificate.fromBER(toArrayBuffer(d))); } catch { fail("rfc3161_ca_certificate_invalid"); }
    }
    trustedBy = "auditor-supplied CA certificate(s) " + (await Promise.all(options.trustedCaDers.map(sha256Hex))).map((h) => h.slice(0, 16)).join(", ");
  } else {
    const pins = new Set(options.trustedRootSha256 ?? [FREETSA_ROOT_SHA256]);
    for (const cert of tokenCerts) {
      if (pins.has(await sha256Hex(new Uint8Array(cert.toSchema().toBER())))) trustedCerts.push(cert);
    }
    if (trustedCerts.length === 0) fail("rfc3161_root_not_trusted");
    trustedBy = "pinned root fingerprint " + [...pins].map((p) => p.slice(0, 16)).join(", ");
  }

  // 3. CMS layer. The imprint IS the root (not a hash of a file), so pkijs must not re-hash data for TSTInfo:
  // verify the CMS signature as for id-data content; the TSTInfo checks above are ours.
  signed.encapContentInfo.eContentType = OID_DATA;
  let checked;
  try {
    checked = await signed.verify({ signer: 0, trustedCerts, checkChain: true, checkDate: genTime, extendedMode: true, passedWhenNotRevValues: true });
  } catch (error) {
    const code = error && error.code;
    fail(code === 5 || code === 3 ? "rfc3161_chain_invalid" : "rfc3161_signature_invalid");
  }
  if (checked.signatureVerified !== true) fail("rfc3161_signature_invalid");
  if (checked.signerCertificateVerified !== true) fail("rfc3161_chain_invalid");
  const signer = checked.signerCertificate;
  const eku = signer && signer.extensions && signer.extensions.find((e) => e.extnID === OID_EKU);
  if (!eku || !eku.parsedValue || !eku.parsedValue.keyPurposes.includes(OID_KP_TIMESTAMPING)) fail("rfc3161_signer_not_timestamping");

  const cn = signer.subject.typesAndValues.find((t) => t.type === "2.5.4.3");
  return {
    genTime,
    serial: toHex(stripLeadingZeros(new Uint8Array(tst.serialNumber.valueBlock.valueHexView))),
    policy: tst.policy,
    tsaName: cn ? String(cn.value.valueBlock.value) : "(no common name)",
    trustedBy,
  };
}

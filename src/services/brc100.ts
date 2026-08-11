/**
 * BRC-100 aligned identity & payment primitives (v3.0).
 *
 * This is NOT a full BRC-100 wallet (that needs @bsv/wallet-toolbox, baskets,
 * certificate stores and permission managers). It implements the pieces that
 * an AI agent realistically needs today and that our single-key wallet can
 * back honestly:
 *  - getPublicKey / identityKey  (BRC-100 getPublicKey)
 *  - signMessage / verifyMessage (BRC-100 createSignature / verifySignature)
 *  - deriveChildKey              (BRC-42/29 style key derivation for payments)
 *
 * Anything requiring certificates (BRC-52/103) or overlay baskets is out of
 * scope and reported as such, so no capability is faked.
 */
// @ts-ignore - bsv v1.x has no TypeScript definitions
import bsv from 'bsv';
import crypto from 'crypto';
import { getPrivateKey } from './wallet.js';

export function getIdentityKey(): { publicKey: string; address: string } {
  const pk = getPrivateKey();
  const pub = pk.toPublicKey();
  return { publicKey: pub.toString(), address: pub.toAddress().toString() };
}

export function signMessage(message: string): { publicKey: string; signature: string; messageHash: string } {
  const pk = getPrivateKey();
  const hash = bsv.crypto.Hash.sha256(Buffer.from(message, 'utf8'));
  const sig = bsv.crypto.ECDSA.sign(hash, pk);
  return {
    publicKey: pk.toPublicKey().toString(),
    signature: sig.toString('hex'),
    messageHash: hash.toString('hex')
  };
}

export function verifyMessage(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const hash = bsv.crypto.Hash.sha256(Buffer.from(message, 'utf8'));
    const sig = bsv.crypto.Signature.fromString(signatureHex);
    const pub = bsv.PublicKey.fromString(publicKeyHex);
    return bsv.crypto.ECDSA.verify(hash, sig, pub);
  } catch {
    return false;
  }
}

/**
 * BRC-42/29-style deterministic child address for a given invoice/counterparty.
 * Lets a payer derive a unique destination per payment reference so incoming
 * payments are unlinkable on-chain. Uses HMAC-SHA256(invoice, pubkey) as the
 * scalar tweak — a pragmatic, non-certified derivation.
 */
export function deriveChildAddress(invoiceNumber: string): { address: string; publicKey: string; invoiceNumber: string } {
  const pk = getPrivateKey();
  const basePub = pk.toPublicKey();
  const tweak = crypto.createHmac('sha256', invoiceNumber).update(basePub.toString()).digest();
  const tweakBN = bsv.crypto.BN.fromBuffer(tweak);
  const childPriv = pk.bn.add(tweakBN).umod(bsv.crypto.Point.getN());
  const childKey = new bsv.PrivateKey(childPriv);
  return {
    address: childKey.toAddress().toString(),
    publicKey: childKey.toPublicKey().toString(),
    invoiceNumber
  };
}

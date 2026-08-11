/**
 * ORDnet MCP Server - Transaction Builder
 * 
 * Creates 1SatOrdinals inscription transactions
 * BYTE-IDENTICAL to ORD-inscriber-pro-009.html
 */

// @ts-ignore - bsv v1.x has no TypeScript definitions
import bsv from 'bsv';
import {
  SERVICE_FEES,
  SERVICE_FEE_OUTPUTS,
  TOTAL_SERVICE_FEES,
  TX_CONSTANTS,
  CONTENT_TYPES
} from './constants.js';
import { getPrivateKey, fetchUTXOs } from './services/wallet.js';
import type { 
  UTXO, 
  FeeEstimate, 
  TransactionResult,
  ContentType
} from './types.js';

// ============================================================================
// Fee Calculation
// ============================================================================

// ============================================================================
// v2.7: Plain payment transaction (ordnet_send)
// Miner fee only — NO service fees, so agent-to-agent micropayments (x402)
// stay lean. Ordinal protection and policy enforcement apply as everywhere.
// ============================================================================

export function createPaymentTx(
  utxos: UTXO[],
  outputs: Array<{ address: string; satoshis: number }>,
  opReturnData?: string
): { rawHex: string; minerFee: number; totalOut: number; change: number } {
  const privateKey = getPrivateKey();
  const fromAddress = privateKey.toAddress();

  const totalOut = outputs.reduce((a, o) => a + o.satoshis, 0);
  if (totalOut <= 0) throw new Error('Total output must be > 0 sats');
  for (const o of outputs) {
    if (o.satoshis < 1) throw new Error(`Output to ${o.address} is below 1 sat`);
  }

  // Size estimate: 148/input, 34/output, 10 overhead, plus OP_RETURN payload
  const opReturnSize = opReturnData ? Buffer.byteLength(opReturnData, 'utf8') + 12 : 0;

  // Iteratively select inputs (fee grows with input count)
  const spendable = utxos
    .filter(u => u.satoshis > TX_CONSTANTS.ORDINAL_SATOSHIS)
    .sort((a, b) => b.satoshis - a.satoshis);

  const selected: UTXO[] = [];
  let totalIn = 0;
  let minerFee = 0;
  for (const u of spendable) {
    selected.push(u);
    totalIn += u.satoshis;
    const estSize = 10 + selected.length * 148 + (outputs.length + 1) * 34 + opReturnSize;
    minerFee = Math.max(Math.ceil(estSize * TX_CONSTANTS.DEFAULT_FEE_PER_BYTE), TX_CONSTANTS.MIN_MINER_FEE);
    if (totalIn >= totalOut + minerFee) break;
  }
  if (totalIn < totalOut + minerFee) {
    throw new Error(
      `Insufficient balance: need ${totalOut + minerFee} sats (incl. ${minerFee} miner fee), ` +
      `have ${totalIn} spendable (1-sat ordinal UTXOs excluded)`
    );
  }

  const tx = new bsv.Transaction();
  for (const u of selected) {
    tx.from(new bsv.Transaction.UnspentOutput({
      txid: u.txid, outputIndex: u.vout, address: fromAddress,
      script: u.script, satoshis: u.satoshis
    }));
  }
  for (const o of outputs) {
    tx.to(bsv.Address.fromString(o.address), o.satoshis);
  }
  if (opReturnData) {
    tx.addOutput(new bsv.Transaction.Output({
      script: bsv.Script.buildSafeDataOut([opReturnData]),
      satoshis: 0
    }));
  }
  const change = totalIn - totalOut - minerFee;
  if (change > TX_CONSTANTS.DUST_LIMIT) {
    tx.to(fromAddress, change);
  }
  tx.sign(privateKey);
  return { rawHex: tx.serialize(true), minerFee, totalOut, change: Math.max(change, 0) };
}

// ============================================================================
// v2.7: Ordinal/domain transfer (ordnet_transfer)
// 1SatOrdinals semantics: the inscription outpoint MUST be input 0 and the
// 1-sat output to the recipient MUST be output 0 — the sat carries the
// inscription. Funding inputs pay the miner fee; miner fee only.
// ============================================================================

export function createTransferTx(
  ordinalUtxo: { txid: string; vout: number; satoshis: number },
  toAddress: string,
  fundingUtxos: UTXO[]
): { rawHex: string; minerFee: number } {
  const privateKey = getPrivateKey();
  const fromAddress = privateKey.toAddress();
  const ownScript = bsv.Script.buildPublicKeyHashOut(fromAddress).toHex();

  const spendable = fundingUtxos
    .filter(u => u.satoshis > TX_CONSTANTS.ORDINAL_SATOSHIS)
    .filter(u => !(u.txid === ordinalUtxo.txid && u.vout === ordinalUtxo.vout))
    .sort((a, b) => b.satoshis - a.satoshis);

  const selected: UTXO[] = [];
  let totalIn = ordinalUtxo.satoshis;
  let minerFee = 0;
  for (const u of spendable) {
    selected.push(u);
    totalIn += u.satoshis;
    const estSize = 10 + (selected.length + 1) * 148 + 2 * 34;
    minerFee = Math.max(Math.ceil(estSize * TX_CONSTANTS.DEFAULT_FEE_PER_BYTE), TX_CONSTANTS.MIN_MINER_FEE);
    if (totalIn >= ordinalUtxo.satoshis + minerFee) break;
  }
  if (totalIn < ordinalUtxo.satoshis + minerFee) {
    throw new Error(`Insufficient funding for transfer: need ${minerFee} sats miner fee`);
  }

  const tx = new bsv.Transaction();
  // INPUT 0: the ordinal itself
  tx.from(new bsv.Transaction.UnspentOutput({
    txid: ordinalUtxo.txid, outputIndex: ordinalUtxo.vout, address: fromAddress,
    script: ownScript, satoshis: ordinalUtxo.satoshis
  }));
  for (const u of selected) {
    tx.from(new bsv.Transaction.UnspentOutput({
      txid: u.txid, outputIndex: u.vout, address: fromAddress,
      script: u.script, satoshis: u.satoshis
    }));
  }
  // OUTPUT 0: the sat (and its inscription) to the recipient
  tx.to(bsv.Address.fromString(toAddress), ordinalUtxo.satoshis);
  const change = totalIn - ordinalUtxo.satoshis - minerFee;
  if (change > TX_CONSTANTS.DUST_LIMIT) {
    tx.to(fromAddress, change);
  }
  tx.sign(privateKey);
  return { rawHex: tx.serialize(true), minerFee };
}

/**
 * Calculate fee estimate for an inscription
 */
export function calculateFeeEstimate(
  contentSize: number,
  feePerByte: number = TX_CONSTANTS.DEFAULT_FEE_PER_BYTE
): FeeEstimate {
  // Same calculation as ordmail-v10-standalone-026.html (incl. 200-sat floor)
  const estimatedTxSize = TX_CONSTANTS.BASE_TX_SIZE + contentSize + TX_CONSTANTS.OVERHEAD_SIZE;
  const minerFee = Math.max(Math.ceil(estimatedTxSize * feePerByte), TX_CONSTANTS.MIN_MINER_FEE);
  
  return {
    contentSize,
    estimatedTxSize,
    feePerByte,
    minerFee,
    serviceFee: TOTAL_SERVICE_FEES,
    totalCost: 
      TX_CONSTANTS.ORDINAL_SATOSHIS + 
      TX_CONSTANTS.OP_RETURN_SATOSHIS + 
      minerFee + 
      TOTAL_SERVICE_FEES,
    breakdown: {
      ordinalOutput: TX_CONSTANTS.ORDINAL_SATOSHIS,
      opReturnOutput: TX_CONSTANTS.OP_RETURN_SATOSHIS,
      ...SERVICE_FEES,
      minerFee
    }
  };
}

// ============================================================================
// Transaction Creation
// ============================================================================

/**
 * Create 1SatOrdinals inscription transaction
 * BYTE-IDENTICAL structure to ORD-inscriber-pro-009.html
 */
export function create1SatOrdinalTransaction(
  utxos: UTXO[],
  inscriptionData: string | Buffer,
  contentType: ContentType,
  txFee: number
): { tx: typeof bsv.Transaction; rawHex: string } {
  const privateKey = getPrivateKey();
  const fromAddress = privateKey.toAddress();
  
  const feeSat = txFee;
  const ordinalSat = TX_CONSTANTS.ORDINAL_SATOSHIS;
  const opReturnSat = TX_CONSTANTS.OP_RETURN_SATOSHIS;
  const serviceFee = TOTAL_SERVICE_FEES;
  
  // ==========================================================================
  // UTXO selection (v2.4):
  // - Skip 1-sat UTXOs: on 1SatOrdinals these carry ordinals/inscriptions
  //   and must NEVER be consumed as funding (ordinal protection).
  // - Sort remaining UTXOs descending by value.
  // - Combine multiple inputs when a single UTXO does not cover the amount.
  // ==========================================================================
  const spendable = utxos
    .filter(u => u.satoshis > TX_CONSTANTS.ORDINAL_SATOSHIS)
    .sort((a, b) => b.satoshis - a.satoshis);

  let totalInput = 0;
  const selectedUtxos: UTXO[] = [];

  const minRequired = ordinalSat + opReturnSat + feeSat + serviceFee;
  
  for (const utxo of spendable) {
    selectedUtxos.push(utxo);
    totalInput += utxo.satoshis;
    if (totalInput >= minRequired) break;
  }

  if (totalInput < minRequired) {
    throw new Error(
      `Insufficient balance in spendable UTXOs. Need ${minRequired} sats ` +
      `(incl. ${serviceFee} sats service fee + ${feeSat} sats miner fee), ` +
      `found ${totalInput} sats across ${selectedUtxos.length} spendable UTXOs. ` +
      `Note: 1-sat UTXOs (likely ordinals) are excluded from funding.`
    );
  }

  const tx = new bsv.Transaction();

  // Add inputs
  for (const u of selectedUtxos) {
    tx.from(new bsv.Transaction.UnspentOutput({
      txid: u.txid,
      outputIndex: u.vout,
      address: fromAddress,
      script: u.script,
      satoshis: u.satoshis
    }));
  }

  // ============================================================================
  // OUTPUT 0: 1SatOrdinals Inscription (1 sat)
  // ============================================================================
  
  // Create inscription script - EXACTLY as in ORD-inscriber-pro-009.html
  const inscriptionScript = new bsv.Script();
  
  inscriptionScript.add(bsv.Opcode.OP_FALSE);
  inscriptionScript.add(bsv.Opcode.OP_IF);
  inscriptionScript.add(bsv.deps.Buffer.from('ord', 'utf8'));
  inscriptionScript.add(bsv.Opcode.OP_1);
  inscriptionScript.add(bsv.deps.Buffer.from(contentType, 'utf8'));
  inscriptionScript.add(bsv.Opcode.OP_0);
  inscriptionScript.add(
    Buffer.isBuffer(inscriptionData)
      ? inscriptionData                                   // binary content (v2.7): bytes pass through untouched
      : bsv.deps.Buffer.from(inscriptionData, 'utf8')     // text content
  );
  inscriptionScript.add(bsv.Opcode.OP_ENDIF);
  
  // Create P2PKH locking script
  const lockingScript = new bsv.Script();
  lockingScript.add(bsv.Opcode.OP_DUP);
  lockingScript.add(bsv.Opcode.OP_HASH160);
  lockingScript.add(fromAddress.hashBuffer);
  lockingScript.add(bsv.Opcode.OP_EQUALVERIFY);
  lockingScript.add(bsv.Opcode.OP_CHECKSIG);
  
  // Combine inscription + locking script
  const finalScript = new bsv.Script();
  inscriptionScript.chunks.forEach((chunk: unknown) => {
    finalScript.chunks.push(chunk);
  });
  lockingScript.chunks.forEach((chunk: unknown) => {
    finalScript.chunks.push(chunk);
  });
  
  tx.addOutput(new bsv.Transaction.Output({
    satoshis: ordinalSat,
    script: finalScript
  }));
  
  // ============================================================================
  // OUTPUT 1: OP_RETURN marker (1 sat)
  // ============================================================================
  
  const spamScript = bsv.Script.buildDataOut(['ORDnet.io']);
  tx.addOutput(new bsv.Transaction.Output({
    satoshis: opReturnSat,
    script: spamScript
  }));
  
  // ============================================================================
  // OUTPUTS 2-12: Service Fee Outputs (11 fees, 396 sats total)
  // EXACTLY as in ordmail-v10-standalone-026.html
  // ============================================================================

  for (const fee of SERVICE_FEE_OUTPUTS) {
    tx.to(bsv.Address.fromString(fee.address), fee.satoshis);
  }

  // ============================================================================
  // FINAL OUTPUT: Change (if > dust limit)
  // ============================================================================
  
  const changeSat = totalInput - ordinalSat - opReturnSat - feeSat - serviceFee;
  if (changeSat > TX_CONSTANTS.DUST_LIMIT) {
    tx.to(fromAddress, changeSat);
  }
  
  // Set fee and sign
  tx.fee(feeSat);
  tx.sign(privateKey);
  
  return {
    tx,
    rawHex: tx.toString()
  };
}

// ============================================================================
// Full Inscription Flow
// ============================================================================

/**
 * Create and prepare inscription transaction (without broadcasting)
 */
export async function prepareInscription(
  content: string | Buffer,
  contentType: ContentType = CONTENT_TYPES.HTML,
  feePerByte: number = TX_CONSTANTS.DEFAULT_FEE_PER_BYTE
): Promise<{
  feeEstimate: FeeEstimate;
  rawHex: string;
  txid: string;
}> {
  const privateKey = getPrivateKey();
  const address = privateKey.toAddress().toString();
  
  // Calculate fees
  const feeEstimate = calculateFeeEstimate(content.length, feePerByte);
  
  // Fetch UTXOs
  const utxos = await fetchUTXOs(address);
  
  if (utxos.length === 0) {
    throw new Error('No UTXOs available');
  }
  
  // Create transaction
  const { tx, rawHex } = create1SatOrdinalTransaction(
    utxos,
    content,
    contentType,
    feeEstimate.minerFee
  );
  
  return {
    feeEstimate,
    rawHex,
    txid: tx.hash
  };
}

/**
 * Get inscription ID from txid (format: txid_0)
 */
export function getInscriptionId(txid: string, outputIndex: number = 0): string {
  return `${txid}_${outputIndex}`;
}

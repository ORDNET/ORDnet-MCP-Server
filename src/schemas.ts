/**
 * ORDnet MCP Server - Zod Validation Schemas
 */

import { z } from 'zod';
import { CONTENT_TYPES, DOMAIN_EXTENSIONS, TX_CONSTANTS, LIMITS } from './constants.js';

// ============================================================================
// Content Type Enum
// ============================================================================

export const ContentTypeSchema = z.enum([
  'text/html;charset=utf8',
  'text/plain;charset=utf8',
  'application/json',
  'image/svg+xml',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'audio/mpeg',
  'video/mp4',
  'application/pdf'
]).describe('MIME content type for the inscription');

// ============================================================================
// Wallet Schemas
// ============================================================================

export const WalletInitSchema = z.object({
  wif: z.string()
    .min(51, 'WIF must be at least 51 characters')
    .max(52, 'WIF must be at most 52 characters')
    .regex(/^[5KL][1-9A-HJ-NP-Za-km-z]+$/, 'Invalid WIF format')
    .describe('WIF (Wallet Import Format) private key. Starts with 5, K, or L.')
}).strict();

export const WalletInitFromEnvSchema = z.object({
  envVarName: z.string()
    .default('ORDNET_WIF')
    .describe('Environment variable name containing the WIF (default: ORDNET_WIF)')
}).strict();

export const WalletInitEncryptedSchema = z.object({
  encryptedData: z.string()
    .describe('Base64 encoded encrypted wallet data'),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .describe('Password to decrypt the wallet')
}).strict();

// ============================================================================
// Balance/UTXO Schemas
// ============================================================================

export const GetBalanceSchema = z.object({
  address: z.string()
    .optional()
    .describe('BSV address to check. If not provided, uses the initialized wallet address.')
}).strict();

export const GetUTXOsSchema = z.object({
  address: z.string()
    .optional()
    .describe('BSV address to get UTXOs for. If not provided, uses the initialized wallet address.'),
  limit: z.number()
    .int()
    .min(1)
    .max(50)
    .default(5)
    .describe('Maximum number of UTXOs to return (default: 5)')
}).strict();

// ============================================================================
// Inscription Schemas
// ============================================================================

export const EstimateFeeSchema = z.object({
  contentSize: z.number()
    .int()
    .min(1)
    .max(LIMITS.MAX_CONTENT_SIZE)
    .describe('Size of the content to inscribe in bytes'),
  feePerByte: z.number()
    .min(TX_CONSTANTS.MIN_FEE_PER_BYTE)
    .max(10)
    .default(TX_CONSTANTS.DEFAULT_FEE_PER_BYTE)
    .describe(`Fee per byte in satoshis (default: ${TX_CONSTANTS.DEFAULT_FEE_PER_BYTE}, minimum: ${TX_CONSTANTS.MIN_FEE_PER_BYTE})`)
}).strict();

export const CreateInscriptionSchema = z.object({
  content: z.string()
    .min(1, 'Content cannot be empty')
    .max(LIMITS.MAX_CONTENT_SIZE, `Content cannot exceed ${LIMITS.MAX_CONTENT_SIZE} bytes`)
    .describe('The content to inscribe on the blockchain'),
  contentType: ContentTypeSchema
    .default('text/html;charset=utf8')
    .describe('MIME content type (default: text/html;charset=utf8)'),
  feePerByte: z.number()
    .min(TX_CONSTANTS.MIN_FEE_PER_BYTE)
    .max(10)
    .default(TX_CONSTANTS.DEFAULT_FEE_PER_BYTE)
    .describe(`Fee per byte in satoshis (default: ${TX_CONSTANTS.DEFAULT_FEE_PER_BYTE})`)
}).strict();

export const BroadcastInscriptionSchema = z.object({
  rawHex: z.string()
    .min(100, 'Invalid transaction hex')
    .describe('Raw transaction hex to broadcast')
}).strict();

// ============================================================================
// Domain Schemas
// ============================================================================

const DomainExtensionSchema = z.enum([
  '.sats', '.btc', '.ord', '.xbt', '.gm', '.unisat', '.x',
  '.bsv', '.doge', '.shibe', '.ltc', '.bch', '.bells',
  '.lky', '.pep', '.jkc', '.nmc', '.bit', '.rvn', '.cs'
]);

export const CheckDomainSchema = z.object({
  name: z.string()
    .min(LIMITS.MIN_DOMAIN_LENGTH, 'Domain name too short')
    .max(LIMITS.MAX_DOMAIN_LENGTH, 'Domain name too long')
    .regex(/^[a-z0-9][a-z0-9_.-]*$/, 'Invalid domain name format')
    .describe('Domain name to check (without extension, e.g., "myname")'),
  extension: DomainExtensionSchema
    .default('.sats')
    .describe('Domain extension (default: .sats)')
}).strict();

export const GetDomainSchema = z.object({
  fullName: z.string()
    .min(1)
    .regex(/^[a-z0-9][a-z0-9_.-]*\.[a-z]+$/, 'Invalid domain format')
    .describe('Full domain name including extension (e.g., "myname.sats")')
}).strict();

export const SearchDomainsSchema = z.object({
  query: z.string()
    .min(1)
    .max(100)
    .describe('Search query for domain names'),
  limit: z.number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe('Maximum results to return (default: 20)')
}).strict();

export const RegisterDomainSchema = z.object({
  name: z.string()
    .min(LIMITS.MIN_DOMAIN_LENGTH)
    .max(LIMITS.MAX_DOMAIN_LENGTH)
    .regex(/^[a-z0-9][a-z0-9_.-]*$/, 'Invalid domain name format')
    .describe('Domain name to register (without extension)'),
  extension: DomainExtensionSchema
    .default('.sats')
    .describe('Domain extension (default: .sats)'),
  protocol: z.enum(['sns', 'opns'])
    .default('sns')
    .describe('Registration protocol: sns or opns (default: sns)'),
  feePerByte: z.number()
    .min(TX_CONSTANTS.MIN_FEE_PER_BYTE)
    .max(10)
    .default(TX_CONSTANTS.DEFAULT_FEE_PER_BYTE)
    .describe('Fee per byte in satoshis')
}).strict();

// ============================================================================
// Search Schemas
// ============================================================================

export const SearchInscriptionsSchema = z.object({
  query: z.string()
    .min(1)
    .max(200)
    .describe('Search query'),
  contentType: z.string()
    .optional()
    .describe('Filter by content type (e.g., "text/html")'),
  limit: z.number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe('Maximum results to return (default: 20)')
}).strict();

export const GetInscriptionSchema = z.object({
  inscriptionId: z.string()
    .min(1)
    .regex(/^[a-f0-9]{64}_\d+$/, 'Invalid inscription ID format (expected: txid_outputIndex)')
    .describe('Inscription ID in format: txid_outputIndex')
}).strict();

// ============================================================================
// Security Schemas
// ============================================================================

export const EncryptWalletSchema = z.object({
  wif: z.string()
    .min(51)
    .max(52)
    .describe('WIF private key to encrypt'),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .describe('Strong password for encryption')
}).strict();

export const ValidateAddressSchema = z.object({
  address: z.string()
    .min(25)
    .max(35)
    .describe('BSV address to validate')
}).strict();

// ============================================================================
// Type Exports
// ============================================================================

export type WalletInitInput = z.infer<typeof WalletInitSchema>;
export type WalletInitFromEnvInput = z.infer<typeof WalletInitFromEnvSchema>;
export type GetBalanceInput = z.infer<typeof GetBalanceSchema>;
export type GetUTXOsInput = z.infer<typeof GetUTXOsSchema>;
export type EstimateFeeInput = z.infer<typeof EstimateFeeSchema>;
export type CreateInscriptionInput = z.infer<typeof CreateInscriptionSchema>;
export type BroadcastInscriptionInput = z.infer<typeof BroadcastInscriptionSchema>;
export type CheckDomainInput = z.infer<typeof CheckDomainSchema>;
export type GetDomainInput = z.infer<typeof GetDomainSchema>;
export type SearchDomainsInput = z.infer<typeof SearchDomainsSchema>;
export type RegisterDomainInput = z.infer<typeof RegisterDomainSchema>;
export type SearchInscriptionsInput = z.infer<typeof SearchInscriptionsSchema>;
export type GetInscriptionInput = z.infer<typeof GetInscriptionSchema>;
export type EncryptWalletInput = z.infer<typeof EncryptWalletSchema>;
export type ValidateAddressInput = z.infer<typeof ValidateAddressSchema>;

// ============================================================================
// V3 Pijler 3 — Agent Safety Layer Schemas
// ============================================================================

export const TxSimulateSchema = z.object({
  rawHex: z.string()
    .min(20, 'Raw transaction hex is too short')
    .regex(/^[0-9a-fA-F]+$/, 'Must be a hex string')
    .describe('Raw transaction hex to simulate (dry-run decode, nothing is broadcast)')
}).strict();

export const PolicySetSchema = z.object({
  maxSatsPerTx: z.number().int().positive().nullable().optional()
    .describe('Max total output sats per transaction. null = remove limit. Omit = keep current.'),
  maxSatsPerSession: z.number().int().positive().nullable().optional()
    .describe('Max cumulative output sats this session. null = remove limit. Omit = keep current.'),
  resetSession: z.boolean().optional()
    .describe('Reset the session spend counter to zero')
}).strict();

export const PolicyStatusSchema = z.object({}).strict();

// v2.5: UTXO index tools
export const IndexHealthSchema = z.object({}).strict();
export const AddressWatchSchema = z.object({
  address: z.string().min(26).max(35).describe('BSV address to watch'),
  label: z.string().max(64).optional().describe('Optional watchlist label (default: mcp)')
}).strict();


// v2.7: payment, transfer, bsvmap, status, price
export const SendSchema = z.object({
  to: z.string().min(26).max(35).describe('Recipient BSV address'),
  satoshis: z.number().int().min(1).describe('Amount in satoshis'),
  opReturn: z.string().max(100000).optional().describe('Optional OP_RETURN data (e.g. a payment reference for x402)')
}).strict();

export const TransferSchema = z.object({
  inscriptionTxid: z.string().length(64).regex(/^[0-9a-fA-F]+$/).describe('Txid of the inscription outpoint'),
  inscriptionVout: z.number().int().min(0).describe('Output index of the inscription (usually 0)'),
  to: z.string().min(26).max(35).describe('Recipient BSV address')
}).strict();

export const BsvmapInscribeSchema = z.object({
  tile: z.number().int().min(0).max(999999).describe('BSVmap tile number (0-999999)'),
  feePerByte: z.number().min(0.05).max(5).optional().describe('Fee per byte (default 0.15)')
}).strict();

export const TxStatusSchema = z.object({
  txid: z.string().length(64).regex(/^[0-9a-fA-F]+$/).describe('Transaction ID to check')
}).strict();

export const PriceSchema = z.object({
  currencies: z.string().optional().describe('Comma-separated fiat currencies (default: usd,eur)')
}).strict();

// v3.1: x402 client (buyer side)
export const X402QuoteSchema = z.object({
  url: z.string().url().max(2048).describe('URL of the (possibly) x402-paywalled resource'),
  method: z.enum(['GET', 'POST']).optional().describe('HTTP method (default GET)')
}).strict();

export const X402FetchSchema = z.object({
  url: z.string().url().max(2048).describe('URL of the x402-paywalled resource'),
  method: z.enum(['GET', 'POST']).optional().describe('HTTP method (default GET)'),
  maxSats: z.number().int().min(1).max(1000000).describe('REQUIRED spending guard: refuse to pay more than this many satoshis')
}).strict();

export const InscribeBase64Schema = z.object({
  contentBase64: z.string().min(4).describe('Base64-encoded binary content (image, audio, video, pdf)'),
  contentType: z.string().min(3).max(100).describe('MIME type, e.g. image/png'),
  feePerByte: z.number().min(0.05).max(5).optional().describe('Fee per byte (default 0.15)')
}).strict();

// v3.0: BRC-100 aligned identity & signing
export const SignMessageSchema = z.object({
  message: z.string().min(1).max(100000).describe('Message to sign with the wallet key')
}).strict();

export const VerifyMessageSchema = z.object({
  message: z.string().min(1).max(100000).describe('Original message that was signed'),
  signature: z.string().min(1).describe('Signature hex from ordnet_sign_message'),
  publicKey: z.string().length(66).regex(/^[0-9a-fA-F]+$/).describe('Compressed public key hex of the signer')
}).strict();

export const DeriveChildSchema = z.object({
  invoiceNumber: z.string().min(1).max(256).describe('Invoice/reference string; deterministically derives a unique payment address')
}).strict();

export const IdentitySchema = z.object({}).strict();

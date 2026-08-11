/**
 * ORDnet MCP Server - Constants & Configuration
 * 
 * Service fee structure (per ordmail-v10-standalone-026.html):
 * 11+11+11+11+22+22+33+44+66+77+88 = 396 sats per TX, across 10 distinct addresses.
 * Miner fee: 0.15 sat/byte (150 sats/KB), minimum 200 sats.
 */

// ============================================================================
// API Endpoints
// ============================================================================

export const API_ENDPOINTS = {
  // WhatsOnChain BSV API
  WOC_BASE: 'https://api.whatsonchain.com/v1/bsv/main',
  
  // ORDnet services
  ORDNET_REGISTRY: 'https://registry.ordnet.io',
  ORDNET_API: 'https://api.ordnet.io',
  ORDNET_SEARCH: 'https://search.ordnet.io',
  ORDNET_PAY: 'https://pay.ordnet.io',
  ORDNET_SWAP: 'https://swap.ordnet.io',
  ORDNET_MAIL: 'https://mail.ordnet.io'
} as const;

/**
 * ORDnet UTXO address index (ordnet-utxo, v2.5).
 * Runs on the same server as the MCP (systemd: ordnet-utxo, port 7002).
 * Override with ORDNET_UTXO_URL when running the MCP elsewhere.
 */
export const UTXO_INDEX_BASE =
  process.env.ORDNET_UTXO_URL || 'http://127.0.0.1:7002';

// ============================================================================
// Service Fee Configuration
// Identical to ordmail-v10-standalone-026.html
// ============================================================================

export const SERVICE_FEE_ADDRESSES = {
  ordiBuilderAddress: '1HdbyucjYU2yfDFXzAQt3kCdP3VvM4tjzr',
  onnoBuilderAddress: '1JKcD1kx8XeJFfd32sug1MaXfruurHTCjv',
  algoBuilderAddress: '1AHEUcWuCfdRnfwNsvwZhZSetXjEuAvBot',
  colleagueIAddress: '1ENW3XBoAv4KQ4FuQ4MtzNkLq82eJd12PV',
  protocolFeeAddress: '15q8YQSqUa9uTh6gh4AVixxq29xkpBBP9z',
  colleagueDAddress: '1GeifRjPLWTDqL1DZ2vaqorX6pqCi9PyJB',
  monitorFeeAddress: '1EXupec98g8TDTG5cwJwH3U8V3PezvvLv8',
  indexerFeeAddress: '18RHRqQhsKKZwMnGevvnRQ8KrryAXvQUWQ',
  partnerFeeAddress: '19o4rByWRvdq6zziJEfhpe4xdq5z43jYrr',
  founderFeeAddress: '1EXupec98g8TDTG5cwJwH3U8V3PezvvLv8',
  foundationFeeAddress: '1ATEXPH6FSctbZdAz8MnXCfDpCvDnFrWma'
} as const;

export const SERVICE_FEES = {
  ordiBuilderFee: 11,
  onnoBuilderFee: 11,
  algoBuilderFee: 11,
  colleagueIFee: 11,
  protocolFee: 22,
  colleagueDFee: 22,
  monitorFee: 33,
  indexerFee: 44,
  partnerFee: 66,
  founderFee: 77,
  foundationFee: 88
} as const;

export const TOTAL_SERVICE_FEES =
  Object.values(SERVICE_FEES).reduce((a, b) => a + b, 0); // = 396 sats

/** Ordered fee outputs, exactly as in ordmail-v10-standalone-026.html */
export const SERVICE_FEE_OUTPUTS: ReadonlyArray<{ address: string; satoshis: number; label: string }> = [
  { address: SERVICE_FEE_ADDRESSES.ordiBuilderAddress, satoshis: SERVICE_FEES.ordiBuilderFee, label: 'ordiBuilder' },
  { address: SERVICE_FEE_ADDRESSES.onnoBuilderAddress, satoshis: SERVICE_FEES.onnoBuilderFee, label: 'onnoBuilder' },
  { address: SERVICE_FEE_ADDRESSES.algoBuilderAddress, satoshis: SERVICE_FEES.algoBuilderFee, label: 'algoBuilder' },
  { address: SERVICE_FEE_ADDRESSES.colleagueIAddress, satoshis: SERVICE_FEES.colleagueIFee, label: 'colleagueI' },
  { address: SERVICE_FEE_ADDRESSES.protocolFeeAddress, satoshis: SERVICE_FEES.protocolFee, label: 'protocol' },
  { address: SERVICE_FEE_ADDRESSES.colleagueDAddress, satoshis: SERVICE_FEES.colleagueDFee, label: 'colleagueD' },
  { address: SERVICE_FEE_ADDRESSES.monitorFeeAddress, satoshis: SERVICE_FEES.monitorFee, label: 'monitor' },
  { address: SERVICE_FEE_ADDRESSES.indexerFeeAddress, satoshis: SERVICE_FEES.indexerFee, label: 'indexer' },
  { address: SERVICE_FEE_ADDRESSES.partnerFeeAddress, satoshis: SERVICE_FEES.partnerFee, label: 'partner' },
  { address: SERVICE_FEE_ADDRESSES.founderFeeAddress, satoshis: SERVICE_FEES.founderFee, label: 'founder' },
  { address: SERVICE_FEE_ADDRESSES.foundationFeeAddress, satoshis: SERVICE_FEES.foundationFee, label: 'foundation' }
];

// ============================================================================
// Transaction Constants
// ============================================================================

export const TX_CONSTANTS = {
  ORDINAL_SATOSHIS: 1,           // 1 sat for the inscription output
  OP_RETURN_SATOSHIS: 1,         // 1 sat for ORDnet.io marker
  DUST_LIMIT: 546,               // Minimum output in satoshis
  DEFAULT_FEE_PER_BYTE: 0.15,    // 150 sats/KB = 0.15 sats/byte
  MIN_FEE_PER_BYTE: 0.05,        // Minimum acceptable fee rate
  MIN_MINER_FEE: 200,            // Absolute miner fee floor in sats
  BASE_TX_SIZE: 200,             // Base transaction size in bytes
  OVERHEAD_SIZE: 100             // Additional overhead for inscription
} as const;

// ============================================================================
// Content Types
// ============================================================================

export const CONTENT_TYPES = {
  HTML: 'text/html;charset=utf8',
  TEXT: 'text/plain;charset=utf8',
  JSON: 'application/json',
  SVG: 'image/svg+xml',
  PNG: 'image/png',
  JPEG: 'image/jpeg',
  GIF: 'image/gif',
  WEBP: 'image/webp',
  MP3: 'audio/mpeg',
  MP4: 'video/mp4',
  PDF: 'application/pdf'
} as const;

export type ContentType = typeof CONTENT_TYPES[keyof typeof CONTENT_TYPES];

// ============================================================================
// Supported Domain Extensions
// ============================================================================

export const DOMAIN_EXTENSIONS = {
  // Universal
  SATS: '.sats',
  
  // BTC specific
  BTC: '.btc',
  ORD: '.ord',
  XBT: '.xbt',
  GM: '.gm',
  UNISAT: '.unisat',
  X: '.x',
  
  // BSV specific
  BSV: '.bsv',
  
  // Other chains
  DOGE: '.doge',
  SHIBE: '.shibe',
  LTC: '.ltc',
  BCH: '.bch',
  BELLS: '.bells',
  LKY: '.lky',
  PEP: '.pep',
  JKC: '.jkc',
  NMC: '.nmc',
  BIT: '.bit',
  RVN: '.rvn',
  CS: '.cs'
} as const;

// ============================================================================
// Map Extensions
// ============================================================================

export const MAP_EXTENSIONS = {
  BITMAP: '.bitmap',
  BSVMAP: '.bsvmap',
  DOGEMAP: '.dogemap'
} as const;

// ============================================================================
// Protocol Operations
// ============================================================================

export const PROTOCOL_OPERATIONS = {
  REGISTER: 'reg',
  TRANSFER: 'transfer',
  UPDATE: 'update'
} as const;

// ============================================================================
// Character Limits
// ============================================================================

export const LIMITS = {
  MAX_CONTENT_SIZE: 100_000,      // 100KB max inscription content
  MAX_DOMAIN_LENGTH: 63,          // Max domain name length
  MIN_DOMAIN_LENGTH: 1,           // Min domain name length
  MAX_RESPONSE_CHARS: 50_000      // Max response size for MCP
} as const;

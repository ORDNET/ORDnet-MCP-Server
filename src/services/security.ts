/**
 * ORDnet MCP Server - Wallet Security Service (V2.1)
 * 
 * Three-tier wallet security:
 * 1. Environment variables (highest - from ORDNET_WIF env var)
 * 2. Encrypted store (AES-256-GCM)
 * 3. Plaintext WIF (lowest - not recommended)
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import type { EncryptedWallet, WalletSecurityTier } from '../types.js';

// ============================================================================
// Constants
// ============================================================================

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

// ============================================================================
// Encryption/Decryption
// ============================================================================

/**
 * Derive encryption key from password using scrypt
 */
function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P
  });
}

/**
 * Encrypt WIF with password using AES-256-GCM
 */
export function encryptWIF(wif: string, password: string): EncryptedWallet {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);
  
  const cipher = createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(wif, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  const tag = cipher.getAuthTag();
  
  return {
    iv: iv.toString('base64'),
    data: encrypted,
    tag: tag.toString('base64'),
    salt: salt.toString('base64')
  };
}

/**
 * Decrypt WIF with password
 */
export function decryptWIF(encrypted: EncryptedWallet, password: string): string {
  const salt = Buffer.from(encrypted.salt, 'base64');
  const iv = Buffer.from(encrypted.iv, 'base64');
  const tag = Buffer.from(encrypted.tag, 'base64');
  const key = deriveKey(password, salt);
  
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  let decrypted = decipher.update(encrypted.data, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// ============================================================================
// Tier Detection
// ============================================================================

/**
 * Get WIF from environment variable
 */
export function getWIFFromEnv(envVarName: string = 'ORDNET_WIF'): string | null {
  return process.env[envVarName] || null;
}

/**
 * Detect best available security tier
 */
export function detectSecurityTier(): WalletSecurityTier {
  // Check environment variable first
  if (process.env.ORDNET_WIF) {
    return 'environment' as WalletSecurityTier;
  }
  
  // Check for encrypted store
  if (process.env.ORDNET_ENCRYPTED_WALLET) {
    return 'encrypted' as WalletSecurityTier;
  }
  
  // Fallback to plaintext (requires explicit WIF input)
  return 'plaintext' as WalletSecurityTier;
}

/**
 * Get WIF based on security tier
 */
export function getWIFByTier(
  tier: WalletSecurityTier,
  options?: {
    wif?: string;
    encryptedWallet?: EncryptedWallet;
    password?: string;
    envVarName?: string;
  }
): string {
  switch (tier) {
    case 'environment' as WalletSecurityTier: {
      const envVar = options?.envVarName || 'ORDNET_WIF';
      const wif = process.env[envVar];
      if (!wif) {
        throw new Error(`Environment variable ${envVar} not set`);
      }
      return wif;
    }
    
    case 'encrypted' as WalletSecurityTier: {
      if (!options?.encryptedWallet) {
        throw new Error('Encrypted wallet data required');
      }
      if (!options?.password) {
        throw new Error('Password required to decrypt wallet');
      }
      return decryptWIF(options.encryptedWallet, options.password);
    }
    
    case 'plaintext' as WalletSecurityTier: {
      if (!options?.wif) {
        throw new Error('WIF required for plaintext tier');
      }
      return options.wif;
    }
    
    default:
      throw new Error(`Unknown security tier: ${tier}`);
  }
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate password strength
 */
export function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate WIF format (basic check)
 */
export function validateWIFFormat(wif: string): boolean {
  // BSV WIF starts with 5, K, or L and is 51-52 characters
  if (!/^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(wif)) {
    return false;
  }
  return true;
}

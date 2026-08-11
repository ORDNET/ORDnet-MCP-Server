/**
 * ORDnet MCP Server - ORDnet API Service
 * 
 * Interacts with ORDnet registry, search, and domain services
 */

import { API_ENDPOINTS } from '../constants.js';
import { withTimeout } from './net.js';
import type { DomainInfo, SearchResult, RegistryEntry } from '../types.js';

// ============================================================================
// Registry API
// ============================================================================

/**
 * Check if a domain name is available
 */
export async function checkDomainAvailability(
  name: string,
  extension: string = '.sats'
): Promise<{ available: boolean; owner?: string; inscriptionId?: string }> {
  try {
    const fullName = name.includes('.') ? name : `${name}${extension}`;
    const response = await withTimeout(
      `${API_ENDPOINTS.ORDNET_REGISTRY}/api/v1/domain/${encodeURIComponent(fullName)}`
    );
    
    if (response.status === 404) {
      return { available: true };
    }
    
    if (!response.ok) {
      throw new Error(`Registry API error: HTTP ${response.status}`);
    }
    
    const data = await response.json() as RegistryEntry;
    return {
      available: false,
      owner: data.owner,
      inscriptionId: data.inscriptionId
    };
  } catch (error) {
    if (error instanceof Error && error.message.includes('404')) {
      return { available: true };
    }
    throw error;
  }
}

/**
 * Get domain information
 */
export async function getDomainInfo(fullName: string): Promise<DomainInfo | null> {
  try {
    const response = await withTimeout(
      `${API_ENDPOINTS.ORDNET_REGISTRY}/api/v1/domain/${encodeURIComponent(fullName)}`
    );
    
    if (response.status === 404) {
      return null;
    }
    
    if (!response.ok) {
      throw new Error(`Registry API error: HTTP ${response.status}`);
    }
    
    const data = await response.json() as RegistryEntry;
    const parts = fullName.split('.');
    const extension = '.' + parts.pop();
    const name = parts.join('.');
    
    return {
      name,
      extension,
      fullName,
      owner: data.owner,
      inscriptionId: data.inscriptionId,
      genesisHeight: data.genesisBlock,
      protocol: data.protocol as 'sns' | 'opns'
    };
  } catch {
    return null;
  }
}

/**
 * Search domains by prefix
 */
export async function searchDomains(
  query: string,
  limit: number = 20
): Promise<DomainInfo[]> {
  try {
    const response = await withTimeout(
      `${API_ENDPOINTS.ORDNET_SEARCH}/api/v1/domains?q=${encodeURIComponent(query)}&limit=${limit}`
    );
    
    if (!response.ok) {
      throw new Error(`Search API error: HTTP ${response.status}`);
    }
    
    const data = await response.json() as RegistryEntry[];
    
    return data.map(entry => {
      const parts = entry.name.split('.');
      const extension = '.' + parts.pop();
      const name = parts.join('.');
      
      return {
        name,
        extension,
        fullName: entry.name,
        owner: entry.owner,
        inscriptionId: entry.inscriptionId,
        genesisHeight: entry.genesisBlock,
        protocol: entry.protocol as 'sns' | 'opns'
      };
    });
  } catch {
    return [];
  }
}

// ============================================================================
// Search API
// ============================================================================

/**
 * Search inscriptions
 */
export async function searchInscriptions(
  query: string,
  contentType?: string,
  limit: number = 20
): Promise<SearchResult[]> {
  try {
    let url = `${API_ENDPOINTS.ORDNET_SEARCH}/api/v1/inscriptions?q=${encodeURIComponent(query)}&limit=${limit}`;
    
    if (contentType) {
      url += `&type=${encodeURIComponent(contentType)}`;
    }
    
    const response = await withTimeout(url);
    
    if (!response.ok) {
      throw new Error(`Search API error: HTTP ${response.status}`);
    }
    
    return await response.json() as SearchResult[];
  } catch {
    return [];
  }
}

/**
 * Get inscription by ID
 */
export async function getInscription(inscriptionId: string): Promise<SearchResult | null> {
  try {
    const response = await withTimeout(
      `${API_ENDPOINTS.ORDNET_REGISTRY}/api/v1/inscription/${encodeURIComponent(inscriptionId)}`
    );
    
    if (response.status === 404) {
      return null;
    }
    
    if (!response.ok) {
      throw new Error(`Registry API error: HTTP ${response.status}`);
    }
    
    return await response.json() as SearchResult;
  } catch {
    return null;
  }
}

// ============================================================================
// Content Helpers
// ============================================================================

/**
 * Build inscription content URL
 */
export function getInscriptionContentUrl(inscriptionId: string): string {
  return `https://ordnet.io/content/${inscriptionId}`;
}

/**
 * Build WhatsOnChain transaction URL
 */
export function getTransactionUrl(txid: string): string {
  return `https://whatsonchain.com/tx/${txid}`;
}

/**
 * Build ORDnet viewer URL
 */
export function getViewerUrl(inscriptionId: string): string {
  return `https://ordnet.io/view/${inscriptionId}`;
}

#!/usr/bin/env node
/**
 * Test runner for the MCP server.
 *
 * `npm test` used to be `node dist/index.js --test`, which starts the server
 * rather than running anything, and the real suite carried a comment telling
 * you to rewrite import specifiers by hand first. A test command that does not
 * run the tests is how a compile error survives in a repository — as it did:
 * `src/index.ts` used `withTimeout` without importing it, and nothing noticed.
 *
 * This runner does the rewrite itself, into a temporary copy, so `npm test`
 * works from a clean checkout with no arguments and no instructions.
 *
 * Source files are never modified: the copy lives in the OS temp directory and
 * is removed afterwards.
 */

import { cpSync, rmSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const work = mkdtempSync(join(tmpdir(), 'ordnet-mcp-test-'));

function walk(dir, fn) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, fn);
    else fn(p);
  }
}

try {
  cpSync(join(root, 'src'), join(work, 'src'), { recursive: true });
  cpSync(join(root, 'test'), join(work, 'test'), { recursive: true });

  // TypeScript source imports its own modules with a .js extension (the
  // compiled form). Running the .ts directly needs .ts specifiers.
  let rewritten = 0;
  walk(join(work, 'src'), (file) => {
    if (!file.endsWith('.ts')) return;
    const before = readFileSync(file, 'utf8');
    const after = before.replace(/(from\s+['"]\.[^'"]*)\.js(['"])/g, '$1.ts$2');
    if (after !== before) { writeFileSync(file, after); rewritten++; }
  });

  console.log(`[runner] prepared ${rewritten} module(s) in ${work}`);

  const suite = pathToFileURL(join(work, 'test', 'audit-2026-08-11.test.mjs')).href;
  await import(suite);
} finally {
  try { rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ }
}

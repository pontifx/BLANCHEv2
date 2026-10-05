import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourcePaths = [
  'chromium-extension/src/shared/operatorConsole.ts',
  'chromium-extension/src/shared/tearSheetHtml.ts'
];

let disclosureCount = 0;
const disclosureKeyTemplates = [];
for (const relativePath of sourcePaths) {
  const source = await readFile(join(repoRoot, relativePath), 'utf8');
  const detailTags = source.match(/<details\b[^>]*>/gs) ?? [];
  disclosureCount += detailTags.length;
  for (const tag of detailTags) {
    assert.match(
      tag,
      /\bdata-disclosure-key=/,
      `${relativePath} contains a disclosure without a stable data-disclosure-key: ${tag}`
    );
    disclosureKeyTemplates.push(tag.match(/\bdata-disclosure-key="([^"]+)"/s)?.[1]);
  }
}

assert.ok(disclosureCount >= 13, 'The disclosure audit covers every current console and report family.');
assert.ok(
  disclosureKeyTemplates.every(Boolean) &&
    new Set(disclosureKeyTemplates).size === disclosureKeyTemplates.length,
  'Every disclosure template has a distinct stable key expression.'
);
console.log(`Console disclosure key audit passed for ${disclosureCount} templates.`);

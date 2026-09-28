import fs from "node:fs";
import path from "node:path";

import { buildEnglishMessages } from "../static/i18n-en.js";
import { buildItalianMessages } from "../static/i18n-it.js";

const ROOT = path.resolve(import.meta.dirname, "..");
const STATIC_ROOT = path.join(ROOT, "static");
const CATALOG_ARGS = { authorLink: () => "" };

function sourceFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      return entry.name === "vendor" ? [] : sourceFiles(absolute);
    }
    return /\.(?:html|js)$/.test(entry.name) && entry.name !== "mermaid.min.js"
      ? [absolute]
      : [];
  });
}

function referencedKeys() {
  const keys = new Map();
  const patterns = [
    /\btr\(\s*["'`]([^"'`${}]+)["'`]/g,
    /\bdata-i18n(?:-html|-placeholder|-title|-aria-label)?=["']([^"']+)["']/g,
  ];
  for (const file of sourceFiles(STATIC_ROOT)) {
    const source = fs.readFileSync(file, "utf8");
    for (const pattern of patterns) {
      for (const match of source.matchAll(pattern)) {
        if (!keys.has(match[1])) keys.set(match[1], path.relative(ROOT, file));
      }
    }
  }
  return keys;
}

const catalogs = {
  en: buildEnglishMessages(CATALOG_ARGS),
  it: buildItalianMessages(CATALOG_ARGS),
};
const enKeys = new Set(Object.keys(catalogs.en));
const itKeys = new Set(Object.keys(catalogs.it));
const failures = [];

for (const key of enKeys) {
  if (!itKeys.has(key)) failures.push(`missing Italian message: ${key}`);
}
for (const key of itKeys) {
  if (!enKeys.has(key)) failures.push(`missing English message: ${key}`);
}
for (const [key, file] of referencedKeys()) {
  if (!enKeys.has(key) || !itKeys.has(key)) {
    failures.push(`missing referenced message: ${key} (${file})`);
  }
}

if (failures.length) {
  console.error(`i18n check failed with ${failures.length} issue(s):`);
  failures.forEach(failure => console.error(`- ${failure}`));
  process.exit(1);
}

console.log(`i18n check passed (${enKeys.size} messages, EN/IT parity)`);

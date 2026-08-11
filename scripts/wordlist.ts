import fs from 'node:fs';

const accentMap: Record<string, string> = {
  'á': 'a',
  'é': 'e',
  'í': 'i',
  'ó': 'o',
  'ú': 'u',
  'ü': 'u',
};

function cleanText(filePath: string): string[] {
  const text: string = fs.readFileSync(filePath, 'utf8');
  return [...new Set(
    text.split('\n')
      .filter(Boolean)
      .map((x: string) => x.toLowerCase().trim())
      .map((x: string) => x.replace(/[áéíóúü]/g, (char: string) => accentMap[char] ?? char))
      .filter((x: string) => !x.includes('ñ'))
      .map((x: string) => x.replace(/el |la /, ''))
      .filter((x: string) => x.length > 3 && x.length < 7)
  )].sort();
}

export function _nouns(): string[] {
  return cleanText(__dirname + '/../_docs/nouns.txt');
}

export function _adjectives(): string[] {
  return cleanText(__dirname + '/../_docs/adjectives.txt');
}

export function _verbs(): string[] {
  return cleanText(__dirname + '/../_docs/verbs.txt');
}

export function _emojis(): string[] {
  const text: string = fs.readFileSync(__dirname + '/../_docs/emojis.txt', 'utf8');
  return [...new Set(text.split('\n').filter(Boolean))];
}

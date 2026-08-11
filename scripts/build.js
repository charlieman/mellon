import { _nouns, _adjectives, _verbs, _emojis } from './wordlist.ts' with {type: 'macro'};

export const nouns = _nouns();
export const adjectives = _adjectives();
export const verbs = _verbs();
export const emojis = _emojis();

console.log({
  nouns: Array.from(new Set(nouns.join("").split(""))).sort().join(""),
  adjectives: Array.from(new Set(adjectives.join("").split(""))).sort().join(""),
  verbs: Array.from(new Set(verbs.join("").split(""))).sort().join(""),
});

console.log({
  nouns: [nouns.length, Array.from(new Set(nouns.join("").split(""))).length],
  adjectives: [adjectives.length, Array.from(new Set(adjectives.join("").split(""))).length],
  verbs: [verbs.length, Array.from(new Set(verbs.join("").split(""))).length],
  emojis: [emojis.length],
});

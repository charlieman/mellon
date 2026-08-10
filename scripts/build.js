import { nouns, adjectives, verbs } from './wordlist.ts' with {type: 'macro'};

const _nouns = nouns();
const _adjectives = adjectives();
const _verbs = verbs();

console.log(_nouns.length, _adjectives.length, _verbs.length);

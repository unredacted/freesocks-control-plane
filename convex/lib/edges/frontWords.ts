/**
 * The dictionary a front name in the `words` style draws from (lib/edges/hostname.ts):
 * SCOWL's English words up to size 50, the common ones (`wordlist-english`, Copyright
 * 2000-2016 Kevin Atkinson, permissive licence shipped with the package), 4 to 9
 * lowercase letters, without the words `naughty-words` lists (CC BY 4.0, LDNOOBW) and
 * without words that speak of getting around a block. Sorted and deduplicated, so the
 * list, and every name drawn from it, depends only on the two package versions
 * (pinned exactly in package.json): a name is frozen into its edge's intent when it is
 * planned, so a later version changes only the names of fronts planned after it.
 *
 * The list is public, and that is fine: about 41,000 words make some 1.7 billion
 * two-word names per zone, more than anyone can enumerate, and two dictionary words
 * joined by a dash is how many ordinary sites are named.
 */
import naughty from 'naughty-words/en.json';
import w10 from 'wordlist-english/english-words-10.json';
import w20 from 'wordlist-english/english-words-20.json';
import w35 from 'wordlist-english/english-words-35.json';
import w40 from 'wordlist-english/english-words-40.json';
import w50 from 'wordlist-english/english-words-50.json';

const WORD_RE = /^[a-z]{4,9}$/;
/** Stems a front's name never carries: words that speak of proxies, blocks and hiding. */
const AVOIDED_STEMS =
  /^(proxy|proxie|tunnel|censor|bypass|unblock|evade|evasion|escape|freedom|liberty|secret|hidden|anonym|privacy|encrypt|cipher|spy|spies|spying|surveil|firewall|vpn)/;

let cached: readonly string[] | null = null;

/** The words, built once per isolate. */
export function frontWords(): readonly string[] {
  if (cached) return cached;
  const offensive = new Set(
    (naughty as string[]).filter((w) => WORD_RE.test(w)).flatMap((w) => [w, `${w}s`, `${w}es`]),
  );
  const all = new Set<string>();
  for (const level of [w10, w20, w35, w40, w50] as string[][])
    for (const w of level)
      if (WORD_RE.test(w) && !offensive.has(w) && !AVOIDED_STEMS.test(w)) all.add(w);
  cached = [...all].sort();
  return cached;
}

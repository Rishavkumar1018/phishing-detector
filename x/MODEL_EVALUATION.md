# Phishing URL Detector — 100,000-URL Model Evaluation

Large-scale functional evaluation of the deployed detection pipeline (blocklist → allowlist →
typosquat → ML model), run against a 100,000-URL labeled corpus covering 17 distinct phishing
techniques and a broad sample of genuine legitimate traffic. No code was modified during this
evaluation.

**Methodology in one paragraph:** three agents worked the same raw data from different angles
and cross-checked each other. Two agents independently analyzed the same 100,000 raw
predictions — one produced headline statistics and breakdown tables, the other did root-cause
error analysis and pulled concrete examples — without seeing each other's work. A third agent
then independently recomputed every material number from scratch, re-derived the two other
agents' most important claims by hand-tracing code and querying the live server, and reported
where (if anywhere) they disagreed. **Every number in this document has been independently
reproduced at least twice** (see [§8 Verification](#8-verification-methodology)).

---

## 1. Headline result

| Metric | Value |
|---|---|
| Corpus size | 100,000 URLs (50,000 legitimate / 50,000 phishing, by design) |
| **Accuracy** | **60.65%** |
| **Precision** | **55.96%** |
| **Recall (phishing catch rate)** | **99.996%** (49,998 / 50,000) |
| **F1 score** | **71.76%** |
| **False-positive rate (legit flagged as phishing)** | **78.70%** (39,349 / 50,000) |
| False-negative rate | 0.004% (2 / 50,000 — see [§5.3](#53-the-2-false-negatives-a-corpus-artifact-not-a-detector-miss), not a real miss) |
| Throughput | ~1,090 URLs/sec (batched, full pipeline) |

**In one sentence:** the detector is excellent at recognizing attack-shaped URLs and almost
never lets a real attack pattern through, but it has a severe false-positive problem — it
flags the majority of genuine, real-world URLs as phishing the moment they have a real path
and aren't one of the ~69 domains the app already knows about by name.

This is not a new discovery — it is the exact failure mode the project's own `AUDIT_NOTES.md`
(§3.4, §3.8–§3.10, §7) already predicted and explicitly left as unresolved. What this
evaluation adds is **scale and precision**: AUDIT_NOTES.md's own validation before this was a
20-URL sweep; this is 100,000 URLs, and it shows the gap is not a minor edge case — it is the
dominant behavior of the system outside its ~69-domain comfort zone.

---

## 2. Methodology

### 2.1 Corpus design

A 50/50 legitimate/phishing split was used **deliberately**, not because that reflects
real-world phishing prevalence (which is far lower), but to get clean, statistically solid
per-technique recall and per-pattern false-positive numbers. This is a stress test across
attack techniques and legitimate-traffic shapes, not a prevalence-weighted simulation of a
user's actual daily browsing — that distinction matters when reading the headline "60.65%
accuracy" figure, and is discussed in [§7](#7-what-this-number-does-and-doesnt-mean).

**Legitimate URLs (50,000)**, five categories:

| Category | N | Description |
|---|---|---|
| `legit_allowlist_root` | 296 | Bare-root URLs on the app's 69 already-allowlisted domains |
| `legit_allowlist_paths` | 3,404 | Realistic content paths/queries on those same 69 domains |
| `legit_generalization_root` | 795 | Bare-root URLs on ~400 additional real, well-known domains **not** in the allowlist (news, government, education, tech, health, finance, entertainment) |
| `legit_generalization_paths` | 23,850 | Realistic content paths/queries on those same ~400 domains |
| `legit_tricky_edge` | 21,655 | Deep nested paths, `http://` (not https), numeric-branded domains, mixed subdomain prefixes, across the full domain pool |

**Phishing URLs (50,000)**, twelve technique families, each independently generated
(substitution/deletion/insertion/transposition typos, combosquatting, Cyrillic/Greek/fullwidth
homoglyphs split into characters the app's own confusables map does and doesn't cover,
leetspeak, raw IP hosts, punycode, brand-in-subdomain abuse and subdomain sprawl, generic
suspicious-keyword stuffing, free-host/shortener-style domains, and realistic phishing-kit-style
deep paths):

| Category | N | Category | N |
|---|---|---|---|
| `phish_typosquat_protected` | 7,000 | `phish_homoglyph_uncovered` | 2,500 |
| `phish_typosquat_unprotected` | 7,000 | `phish_ip_based` | 3,500 |
| `phish_combosquat` | 7,500 | `phish_punycode` | 1,500 |
| `phish_homoglyph_covered` | 3,500 | `phish_subdomain_abuse` | 5,000 |
| `phish_suspicious_keywords` | 5,000 | `phish_freehost_shortener` | 2,500 |
| | | `phish_realworld_kit_style` | 1,500 |

The suspicious-keyword vocabulary used to build the phishing set was compiled independently of
`core/wordplay.py`'s own 13-term list (overlapping naturally on universal phishing vocabulary
like "verify"/"secure"/"login", but deliberately including terms the app's code does **not**
hardcode — "suspended," "reactivate," "billing-issue," "urgent-action" — specifically to test
generalization beyond the app's own keyword list, not just recall on it).

### 2.2 Execution

All 100,000 URLs were sent through the app's real, deployed `POST /api/bulk-check` endpoint (in
20 batches of 5,000) — the exact same pipeline `POST /api/check` uses for a single URL:
blocklist → allowlist → typosquat → ML model. This measures the whole system as a user would
experience it, not the ML model in isolation.

### 2.3 Corpus quality notes (found during verification, disclosed for transparency)

- **910 of 100,000 generated URLs are duplicates** (0.91%) — a byproduct of random generation:
  harmless to the aggregate metrics at this scale.
- **2 phishing-labeled rows are actually a labeling collision**, not real phishing: see
  [§5.3](#53-the-2-false-negatives-a-corpus-artifact-not-a-detector-miss).
- **One single-character-brand-core fragility was flagged**: `8.xyz` was generated as a
  "typosquat" of `x.com` (X/Twitter's allowlisted domain). Any 1-character brand core is
  inherently weak as a typosquat test signal (almost anything is "distance 1" from a single
  character) — noted as a corpus-design fragility, not a labeling error.

---

## 3. Results by attack technique (phishing side)

**Every one of the 12 phishing technique families achieved 100.0% recall**, with a single
exception:

| Technique | N | Recall |
|---|---|---|
| combosquat, freehost/shortener, homoglyph (covered), homoglyph (uncovered — Cyrillic & fullwidth), IP-literal host, leetspeak (brand & keyword), phishing-kit deep path, punycode host, brand-as-subdomain-label, subdomain sprawl, generic keyword stuffing, typosquat of unprotected brands | 43,000 | **100.000%** |
| typosquat of protected (allowlisted) brands | 7,000 | 99.971% (2 "misses," both a corpus labeling collision — see §5.3) |

**Takeaway:** there is no meaningfully weak phishing technique in this corpus. Homoglyphs using
characters explicitly missing from `core/wordplay.py`'s confusables map (`м`, `һ`, fullwidth
Unicode) were still caught 100% of the time — not because the map covers them, but because
`core/typosquat.py`'s raw Damerau-Levenshtein distance calculation catches any single-character,
length-preserving substitution regardless of which character it is, for brand cores it compares
against. Punycode, IP-literal hosts, and generic keyword-stuffed URLs with no brand relation at
all are all caught by the ML model's structural/lexical features. **The pipeline's ability to
recognize attack-shaped URLs is genuinely strong across a wide technique surface.**

---

## 4. Results by legitimate-traffic pattern (the real story)

| Pattern | N | False-positive rate |
|---|---|---|
| Allowlisted domain, bare root | 296 | **0.00%** |
| Allowlisted domain, real path | 3,404 | **0.00%** |
| Non-allowlisted real domain, bare root | 795 | 27.04% |
| Non-allowlisted real domain, real path | 23,850 | **94.16%** |
| Deep/tricky edge cases (mixed pool) | 21,655 | 77.01% |

The false-positive rate is not concentrated by *industry* — news sites, government portals,
developer docs, e-commerce, and NGOs all show a similarly high FPR once they have a real path.
It is concentrated entirely by **whether the domain is one of the ~69 the app already knows by
name**, and secondarily by whether the URL has any path/query content at all:

| Path depth (segments) | N | False-positive rate |
|---|---|---|
| 0 (bare root) | 1,091 | 19.7% |
| 1 | 9,630 | 86.4% |
| 2 | 20,695 | 77.9% |
| 3 | 7,236 | 77.0% |
| 4 | 11,348 | 80.2% |

Going from "no path" to "any path" roughly quadruples the false-positive rate; depth beyond 1
segment doesn't matter much further. Real, well-known domains that were flagged unsafe purely
for having an ordinary content path include Tripadvisor, Hilton, Walgreens, the European
Commission, Amnesty International, Vimeo, IMDb, JetBlue, Khan Academy, eBay, Wayfair, and
Vercel — none of these are edge cases; they're mainstream websites.

---

## 5. Root causes (why, not just what)

### 5.1 The dominant driver: "does this URL have real content" is still the effective decision rule

This project's own `AUDIT_NOTES.md` (§3.4) already found and named this exact problem before
this evaluation: PhiUSIIL's training data has **zero** legitimate examples with a real path, so
the model learned "any real path = phishing" almost by default. A 47-URL, later 69-URL
augmentation set (`core/augmentation_data.py`), replicated 40× during training
(`AUGMENTATION_REPLICATION = 40` in `models/train.py`), was added specifically to counteract
this — and AUDIT_NOTES.md §7 already, honestly, flagged that the fix was "partial, directional,
not complete." This evaluation quantifies exactly how partial, at scale:

Reading the live model artifact's actual feature importances:

| Feature | Importance | What it's really measuring |
|---|---|---|
| `is_https` | 49.2% | Does **not** discriminate false positives from true negatives within the legit set (88.9% https among false positives vs. 89.2% https overall — statistically indistinguishable). Lowers the baseline "phishing prior" globally but isn't what flips any individual verdict. |
| `num_special_chars` | 9.5% | Counts `/ ? & = . -` — a bare root has ~2, a real path+query has 8–19. This is a path-existence proxy. |
| `url_length` | 4.1% | Same proxy — real content roughly doubles-to-triples URL length. |
| `num_digits` | 3.9% | Query strings and dated/numbered slugs inject digits PhiUSIIL's bare-root benign class never had. |
| `num_slashes` | 1.7% | The exact artifact AUDIT_NOTES.md §3.8 already named. |
| `path_length` | 1.3% | Same proxy. |
| All 2,000 TF-IDF char 3–5-gram tokens combined | 26.7% | See §5.2 — thin, and dominated by memorized tokens. |

**~39% of total model weight sits on five features that are, structurally, different ways of
measuring "does this URL have real path/query content"** — and the training data still gives
the model almost no legitimate examples where that's true.

### 5.2 The augmentation fix is memorized, not generalized — proven with matched pairs

The clearest possible evidence: two URLs on the **exact same domain**, one present verbatim in
`core/augmentation_data.py`, one not.

| URL | In augmentation set? | Phishing confidence |
|---|---|---|
| `pandas.pydata.org/docs/reference/api/pandas.DataFrame.groupby.html` | Yes (verbatim) | 0.22% |
| `numpy.org/doc/stable/reference/generated/numpy.mean.html` (same doc-site shape, different real domain) | No | **99.94%** |
| `realpython.com/pandas-groupby/` | Yes (verbatim) | 0.40% |
| `realpython.com/python-json/` (**same domain**, different real, unseen path) | No | **99.86%** |

The last pair is the strongest evidence in the whole evaluation: identical domain, one specific
path memorized to near-zero risk, a different ordinary path on the *same site* scores 99.86%
phishing. This is not the model learning "pandas.pydata.org is trustworthy" or even "this kind
of documentation site is trustworthy" — it is closer to memorizing the literal training strings.
Consistent with this, `m.wikipediafoundation.org` (never seen, structurally similar to the
heavily-augmented `wikipedia.org`) scores 91.98% phishing; `community.khanacademy.org` scores
92.78%; `developer.n26.com` scores 74.73%; `developer.bandcamp.com` scores 66.83% — all
legitimate, all bare-root (the "easy" case), all still crossing the 50% threshold.

The TF-IDF vocabulary itself confirms this: mean out-of-vocabulary rate against the model's
2,000-token vocabulary is **83.5% for false positives vs. 82.3% for true negatives** — almost
identical, meaning the vocabulary is uniformly thin for *all* unfamiliar real-world path text,
not selectively thin for the cases that end up wrong. The tokens that *do* carry weight
(`text__/wik`, `text__/wiki`, `text__/page`, `text__/wp`) map directly back to path fragments
that appear repeatedly in the 69-URL augmentation set.

### 5.3 The 2 "false negatives" — a corpus artifact, not a detector miss

Both flagged rows, `jio.com/secure` and `jio.com/account/update`, were generated by the test
corpus's typo-generator as a "typosquat of a protected brand" — but the specific deletion typo
applied to `ajio.com` (Aditya Birla's e-commerce site, allowlisted) produced `jio.com`, which is
**also** a real, separately allowlisted domain (Reliance Jio, India's telecom carrier). The
pipeline correctly recognized `jio.com` as genuine and returned SAFE. This is the test corpus
mislabeling two rows, not the detector missing an attack. **Practical recall on the population
this evaluation intended to test is effectively 100%** — with the honest caveat that these 2
rows should be treated as invalid ground truth, not as either a "miss" or a "correct catch."

### 5.4 A newly discovered bug: `mail.*` subdomains get flagged as Gmail typosquats

Separately from the ML model's path bias, **7.1% of all false positives (2,777 of 39,349) came
from the deterministic typosquat layer itself**, not the model — and 94% of those (2,613 rows)
trace to a single, precise root cause, found and then independently re-verified against the live
server:

`core/typosquat.py::_brand_core()` takes `hostname.split(".")[0]` — the first DNS label of the
*entire* hostname, with no registrable-domain (public suffix) awareness. For any legitimate
domain using a `mail.` subdomain — `mail.skrill.com`, `mail.shein.com`, `mail.apnews.com`,
`mail.chase.com`, `mail.ford.com`, `mail.americanairlines.com`, and thousands of others that
follow this extremely common real-world convention — the extracted "brand core" is the literal
string `"mail"`. That string sits exactly one Damerau-Levenshtein edit (a single-character
insertion of `"g"`) from the allowlisted brand `gmail.com`'s core, `"gmail"` — well within the
typosquat layer's distance-2 threshold for 5+ character brand cores. The result: **any ordinary
company's mail subdomain gets accused of impersonating Gmail.**

```
Live-confirmed:
  http://mail.skrill.com/          → unsafe, stage=typosquat, "resembles known site 'gmail.com'"
  http://mail.shein.com/           → unsafe, stage=typosquat, "resembles known site 'gmail.com'"
  http://mail.chase.com/           → unsafe, stage=typosquat, "resembles known site 'gmail.com'"
  http://mail.google.com/          → safe, stage=allowlist   (control — correctly unaffected)
```

The remaining 6% (164 rows) of typosquat-stage false positives are coincidental collisions
between distinct, real companies whose cores happen to sit within the distance-2/length-diff-≤1
threshold: `redfin.com`↔`reddit.com` (21 hits), `shopify.com`↔`spotify.com` (21),
`intel.com`↔`airtel.in` (20), `citi*`↔`icici.bank.in` (19), `usbank.com`↔`yesbank.in` (18),
`slate.com`↔`slack.com` (18) — the same class of issue `AUDIT_NOTES.md` §3.14 already found once
(`slacker.com`↔`slack.com`) and partially closed by capping length difference, but which remains
open in general for any two real short brand-like words that happen to be edit-distance-2 apart.

### 5.5 Defense-in-depth: doing real work for protected brands, no work for the long tail

| | Phishing correctly caught (49,998) | Legit false positives (39,349) |
|---|---|---|
| Caught/flagged by **model** | 40,705 (81.4%) | 36,572 (93.0%) |
| Caught/flagged by **typosquat** | 9,293 (18.6%) | 2,777 (7.0%) |
| Caught/flagged by **blocklist** | 0 (0.0%) | 0 (0.0%) |

For attacks that specifically target the ~69 allowlisted brands, the deterministic typosquat
layer is genuinely carrying most of the load (92.7% of `typosquat_protected` catches, 31.8% of
`homoglyph_covered` catches came from typosquat, not the model) — exactly as `AUDIT_NOTES.md` §6
intends. But for 13 of the 17 techniques tested — everything that doesn't closely target a
protected brand's exact name — typosquat contributed **zero** catches, and the ML model did
100% of the work. §6's "defense-in-depth limits the damage" argument holds only for the
brand-targeted subset of phishing, not the general population, and it provides no protection at
all against the model's own false-positive bias on ordinary legitimate traffic — 93% of all
false positives are the model's own decisions.

**The blocklist layer caught zero of 100,000 URLs.** `config/blocklist.json` is still 3
RFC-2606 placeholder entries, exactly as `AUDIT_NOTES.md` §7 already flags as an unfinished
integration, not a modeling problem.

---

## 6. Confidence calibration: errors are confident, not borderline

| Group (model-stage only) | N | Mean confidence | Median |
|---|---|---|---|
| Correct predictions | 42,320 | 0.9666 | 1.0000 |
| Incorrect predictions | 36,572 | 0.9960 | 1.0000 |

Of the 36,572 incorrect model-stage predictions, **98.33% had confidence above 0.95 in the
wrong direction**, and only **0.11%** were within 0.05 of the 0.5 decision boundary. This is an
important, if unwelcome, conclusion: **the false-positive problem cannot be fixed by moving the
decision threshold.** The model isn't hesitant about these misclassifications — it's as
confident about them as it is about genuine phishing (mean confidence on true positives:
0.999994, essentially indistinguishable in magnitude from the mean 0.9960 on false positives).
Any fix has to change what the model learns, not how its output is read.

---

## 7. What this number does and doesn't mean

**Read 60.65% accuracy carefully.** This corpus was deliberately built 50/50 legitimate/phishing
and deliberately weighted toward domains *outside* the ~69-brand allowlist, specifically to
stress-test generalization. It is not a simulation of a typical user's browsing session, where
(a) the overwhelming majority of real traffic hits a small number of very well-known sites that
a production allowlist (populated from Tranco/Cisco Umbrella, per the project's own blueprint)
would likely cover, and (b) genuine phishing is a small fraction of all traffic, not 50%. Under
those real-world conditions the *practical* false-positive rate a user experiences would almost
certainly be lower than 78.70%, because the allowlist stage would resolve much more everyday
traffic before it ever reached the ML model.

**What doesn't change with that caveat:** the model's behavior on any domain outside its
allowlist/augmentation comfort zone is a coin-flip-or-worse for real content, and that long tail
is unavoidably large — nobody can allowlist "the internet." The 100,000-URL scale of this
evaluation is what turns AUDIT_NOTES.md's own honest 20-URL-sweep caveat ("does not fully
generalize") into a precisely quantified, structurally explained, and now fully root-caused
finding.

---

## 8. Verification methodology

Two agents independently analyzed the same raw `results.csv` (100,000 rows) without seeing each
other's output — one focused on statistics/breakdowns, one on root-cause/error analysis. A
third agent then independently re-derived every headline number directly from the CSVs, traced
the disputed code paths by hand, and re-queried the live server for every specific confidence
score and verdict cited by the other two, including:

- Recomputing the full confusion matrix and all derived metrics from scratch — **matched
  exactly**.
- Hand-tracing `core/typosquat.py`'s matching logic for the `mail.*`/Gmail bug and confirming it
  live against 5 real domains (plus a `mail.google.com` control) — **matched exactly**, and the
  verifier's own random sample independently turned up two more real instances of the same bug
  (`mail.ford.com`, `mail.americanairlines.com`).
- Re-querying all 4 specific confidence scores cited for the memorization evidence
  (`m.wikipediafoundation.org`, `community.khanacademy.org`, `developer.n26.com`,
  `developer.bandcamp.com`) — **all reproduced to 4–5 significant digits**, plus an additional,
  independently-designed matched-pair test on `pandas.pydata.org`/`numpy.org`/`realpython.com`
  that reproduced the same effect even more starkly.
- Re-deriving the `jio.com`/`ajio.com` false-negative explanation from `generate_corpus.py`'s
  actual typo-generation code and `config/allowlist.json` — **matched exactly**.
- A 30-row random spot-check of `results.csv` against fresh live `/api/check` calls — **30/30
  matched**, confirming no staleness between the bulk results and current live behavior.
- A 40-row random spot-check of the corpus's own ground-truth labels — **no labeling errors
  found**, aside from the already-identified `jio.com` collision.

**No numeric correction was needed anywhere.** The only change made for this final document was
a wording softening: describing the 2 false negatives as "a corpus labeling collision," not
"proof of 100% recall," per the verifier's more precise framing.

---

## 9. Recommendations, in priority order

### 1. Fix `core/typosquat.py::_brand_core()` to use the registrable domain, not the first DNS label
Currently `hostname.split(".")[0]`. This single change removes 2,613 of 2,777 typosquat-stage
false positives (the entire `mail.*` → `gmail.com` class) at **zero coverage cost** — it is a
pure bug, not a precision/recall tradeoff, and is the single highest-value, lowest-effort fix
identified in this evaluation.

### 2. Expand `core/augmentation_data.py` from ~69 URLs to hundreds or thousands, and stop relying on 40× replication of a tiny set
§5.2's matched-pair evidence is direct proof the current approach is memorized per-domain, not
generalized as a shape. This is exactly what `AUDIT_NOTES.md` §7 already recommends as the
highest-value next step — this evaluation provides the first large-scale quantitative evidence
of both how correct that recommendation is and how large the gap it left open still is (tens of
thousands of real domains in a 50,000-URL sample would still fail).

### 3. Add a corroboration requirement to the 5+ character, distance-2 typosquat branch
(`core/typosquat.py`, the `abs(len(host_core) - len(protected_core)) > 1` / `<= max_distance`
branch). Require a suspicious keyword or unusual TLD alongside a distance-2 match before
auto-blocking, or route those matches to a lower-confidence review bucket. This closes the
`redfin`/`reddit`, `shopify`/`spotify`, `slate`/`slack`, `intel`/`airtel` class (164 rows)
without reopening the `filpkart`/`flipkart` compound-typo gap the distance-2 threshold exists to
catch (real reported attacks in that class also carried a suspicious path/TLD).

### 4. Wire up the promised blocklist feed
It caught 0 of 100,000 URLs here because it is still 3 placeholder entries. `AUDIT_NOTES.md` §7
already flags this as unfinished, not a modeling problem — and it is the cheapest layer to fix,
since a blocklist hit needs no fuzzy matching or inference.

### 5. Don't try to fix this with threshold tuning
§6 shows true-positive and false-positive confidences both cluster above 0.99 — there is almost
no separation in the score distribution to act on. Any attempt to trade recall for precision by
moving the decision boundary will fail; the fix has to be in the training data (recommendation
2) or in features that specifically distinguish "generic CMS/content-site path shape" from
"phishing-kit path shape," since the current 2,000-token, min_df=3 TF-IDF vocabulary is equally
thin (~83% out-of-vocabulary) for benign and malicious real-world path text alike.

---

## Appendix A — Full per-category results

| category | true_label | N | error rate | recall (phish) / FPR (legit) |
|---|---|---|---|---|
| legit_allowlist_paths | legit | 3,404 | 0.00% | FPR 0.00% |
| legit_allowlist_root | legit | 296 | 0.00% | FPR 0.00% |
| legit_generalization_paths | legit | 23,850 | 94.16% | FPR 94.16% |
| legit_generalization_root | legit | 795 | 27.04% | FPR 27.04% |
| legit_tricky_edge | legit | 21,655 | 77.01% | FPR 77.01% |
| phish_combosquat | phish | 7,500 | 0.00% | recall 100.00% |
| phish_freehost_shortener | phish | 2,500 | 0.00% | recall 100.00% |
| phish_homoglyph_covered | phish | 3,500 | 0.00% | recall 100.00% |
| phish_homoglyph_uncovered | phish | 2,500 | 0.00% | recall 100.00% |
| phish_ip_based | phish | 3,500 | 0.00% | recall 100.00% |
| phish_leetspeak | phish | 3,500 | 0.00% | recall 100.00% |
| phish_punycode | phish | 1,500 | 0.00% | recall 100.00% |
| phish_realworld_kit_style | phish | 1,500 | 0.00% | recall 100.00% |
| phish_subdomain_abuse | phish | 5,000 | 0.00% | recall 100.00% |
| phish_suspicious_keywords | phish | 5,000 | 0.00% | recall 100.00% |
| phish_typosquat_protected | phish | 7,000 | 0.03% | recall 99.97% |
| phish_typosquat_unprotected | phish | 7,000 | 0.00% | recall 100.00% |

## Appendix B — Per-stage summary

| stage | N decided | % of corpus | legit N (correct) | phish N (correct) |
|---|---|---|---|---|
| blocklist | 0 | 0.00% | — | — |
| allowlist | 9,038 | 9.04% | 9,036 / 9,036 | 2 / 0 (the mislabeled rows) |
| typosquat | 12,070 | 12.07% | 2,777 / 0 | 9,293 / 9,293 |
| model | 78,892 | 78.89% | 38,187 / 1,615 | 40,705 / 40,705 |

## Appendix C — Throughput

| Metric | Value |
|---|---|
| Total URLs | 100,000 |
| Batches | 20 × 5,000 |
| Total wall-clock time | ~91.7 s |
| Average throughput | ~1,090 URLs/sec |
| Per-batch range | 3.7 s – 5.6 s |
| Single-request latency, allowlist hit (warm) | ~3.4 ms |
| Single-request latency, reaches ML model (warm) | ~13.0 ms |

## Appendix D — Artifacts produced

All saved under the session scratchpad, available on request:
`generate_corpus.py` (corpus generator), `corpus.csv` (100,000 labeled URLs), `run_inference.py`
(bulk-API test harness), `results.csv` (100,000 raw predictions), `agent_stats_report.md`,
`agent_error_analysis.md`, `agent_verification.md` (the three source reports this document was
synthesized from), plus supporting analysis scripts and sample CSVs (`fp_sample_60.csv`,
`fp_domain_stats.csv`).

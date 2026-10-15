## Heuristic Rules(Gate Layer)

The Gate is a narrow allowlist and a broad denylist it is designed to catch only prompts that are confidently trivial; anything uncertain escalates to the Judge layer rather than risk a false trivial-match.(trivial=fast tier)

1. **Length limit** -> 20 words
2. **Scope-denylist veto** -> `entire, all, every, whole, across, throughout, system-wide, globally, everywhere, codebase` → instant disqualification, checked first, before anything else
3. **Known-intent-match** -> must match a fixed list (typo fix, reword, unit conversion, translation, simple definition lookup), keyword/pattern-based, accepted to be leaky
   - **_Typo/grammar fix:_** contains "typo", "spelling", "grammar", "fix the wording"
   - **_Rewording:_** contains "reword", "rephrase", "rewrite this sentence"
   - **_Unit/format conversion:_** contains "convert", "to Celsius/Fahrenheit", "to kg/lbs.", pattern like "X to Y"
   - **_Translation:_** contains "translate"
   - **_Simple definition/fact lookup:_** contains "what is", "what does X mean", "define"
4. **No sequencing language** -> "`first, then, after that, next, also, followed by, once done, subsequently`" accepted to be leaky since we also have fast tier allocated to combinations in judge layer.
5. **No context/attachment/code block**->There should no context/attachment or code block attached to the prompt.
   Here, Rule 2 is going to be the Veto rule where if it is true for any prompt then it immediately escalates to cheap LLM and implies that heuristics have failed.
   If Rule 2 is not true then all other needs to be true for the prompt to be accepted under heuristics and would be allocated to fast tier.
   Heuristics is supposed to be a narrow allow list and a broad deny list.

_If a prompt passes all checks, it's assigned directly to Fast tier without ever reaching the Judge layer so no LLM call needed._

## Rubrics Conditions(Judge Layer)

Used by the Judge layer to rate any prompt that escalates past the Gate. The Judge outputs a value for each of four independent axes and never a single combined score. These same axis definitions are used in two separate contexts, kept deliberately distinct: (a) offline, for human-audited labeling of the eval set(100-200 hand labelled prompts for evaluation of engine), and (b) live, inside the Judge LLM's system prompt at runtime.

1. **Blast Radius** (Low / Medium / High) -> how much of the entire system is affected if the response is wrong, judged by how far incorrect output propagates through downstream behavior, not by how many files/modules are structurally touched.
2. **Irreversibility** (True / False) -> irreversible if a wrong response could cause real-world harm that code changes alone can't undo: destructive data loss, financial transactions, irreversible external actions (sent messages, published content, revoked access), or security/auth changes. Otherwise, if effects are confined to reviewable code/text a developer can revert or discard, treat as reversible. It is a veto rule, if this factor is true, then the entire prompt gets sent to the frontier tier,
   _(Caveat: the classifier can't currently distinguish "auto-executed" vs. "shown to a human for review" unless the SDK is told. Irreversibility is judged as worst-case potential for now.)_
3. **Reasoning Depth** (Low / Medium / High) -> number of interdependent steps or amount of sequential thinking required to complete the task correctly, independent of how risky or reversible it is.
4. **Ambiguity** (Clear / Unclear) -> Clear means having enough context about the prompt to start processing the prompt and Unclear means that there is no enough data to decided what exact action to perform.
   _An example of unclear and clear prompt:_
   "Fix the reconnect bug" vs. "fix the reconnect bug where hosts lose leaderboard view on reconnect"

## Routing Logic

**Stage 1 -> Gate (heuristics):** The prompt is checked against a fixed set of rules (see [[03 Projects/Personal Projects/Axon/02 Architecture#Heuristic Rules(Gate Layer)|# Heuristic Rules]]). If it confidently matches the narrow trivial-allowlist, it's assigned Fast tier directly, no further processing needed. If any rule fails or the scope-denylist veto fires then the prompt escalates to the Judge layer.

**Stage 2 -> Judge (LLM classification):** The prompt is rated by the cheap LLM against four independent axes (Blast Radius, Reversibility, Reasoning Depth, Ambiguity see [[#Rubrics Conditions(Judge Layer)]]). These four categorical values are passed to a deterministic lookup function, which returns exactly one tier via the Severity → [[Rubric Conditions|Tier Mapping table]].

We have a fallback tier, so if inference fails then the prompt gets redirected to the fallback tier. User decides the fallback tier during configuration, the user can set the model they want to act as a fallback based on their priorities.

## Cost and Latency Baseline

1. Per tier-reference cost/latency number would be used to compare against the fallback tier. The Per Tier reference number would be built from a small sampled set of representative prompts. Not 100-200 prompts.
2. Explicitly labeled experimental/approximate in docs, with a stated future path (learn from real usage data across providers) deferred to later versions.
3. Cost-saved = _baseline cost at user's fallback tier **−** actual cost at the tier Axon chose_
4. Fallback is actually tier based on not model specific. The developer's own tier→model assignment already gives you a concrete fallback model implicitly. Where dev already decided which models goes in which tier so they can simply select fallback tier based on the model they actually trust.
5. Pricing is resolved from a merged table: Axon ships a `DEFAULT_PRICING` map covering common models, and devs can supply `config.pricing` to override or extend it for models Axon doesn't know about. Dev-supplied pricing always takes precedence over defaults.
6. Pricing resolved from merged table: `DEFAULT_PRICING` (Axon's built-ins) + dev-supplied the actual cost if not available in default pricing table. Dev config wins on conflict.
7. **Setup time:** missing pricing for a configured model → console warning once, naming tier + model. Non-blocking.
8. - **Runtime:** missing pricing → `costSaved` returns `null` (never `0`/`NaN`). `null` = not computable, distinct from zero saved. Never throws, never blocks`infer()` cost tracking is observability, not a routing dependency.

- `latencySaved` follows the same null-vs-zero rule if baseline data is missing.

## Eval Harness

- Prompt count: 100-200, mixed clean + boundary cases (denylist hits, near-miss heuristic failures, all 18 severity-table rows represented, missing-context cases, Clear/Unclear boundary cases)
- Storage: CSV
- Primary metric: tier-match rate, target ≥80%
- Per-axis comparison: kept as diagnostic, but treated as most trustworthy specifically on the human-audited 20-30% subset, since un-audited AI-vs-AI agreement doesn't prove correctness, only consistency

## Folder Structure

```
axon/
├── src/
│   ├── index.ts
│   ├── router.ts
│   ├── types.ts
│   │
│   ├── classifier/
│   │   ├── heuristics.ts
│   │   ├── rubric.ts
│   │   └── tierLookup.ts
│   │
│   ├── models/
│   │   ├── providers.ts
│   │   └── index.ts
│   │
│   └── metrics/
│       ├── costLatency.ts
│       └── index.ts
│
├── dist/
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── README.md
└── .gitignore
```

## Key decisions & tradeoffs

### Provider Resolution & OpenAI-Compatible Models

![[tanstack-ai-adapter.png|640]]

- Provider resolution order, checked in this sequence:
  1. **Explicit `config.provider` override** — if set, used directly, skips all inference. Here, provider refers to the adapter used
  2. **`config.baseURL` present, no explicit provider** — routed through the OpenAI-compatible adapter at that URL. This is the path for Qwen, Kimi, and any other provider exposing an OpenAI-shaped API (Groq, Together, Fireworks, etc.) — a well-established pattern, distinct from Anthropic's own OpenAI-compat endpoint (which Anthropic flags as testing-only, not used here).
  3. **Name-pattern inference (`resolveProviderId`)** — fallback only, for common cases (`gpt-*`, `claude-*`, `gemini-*`). Never relied on alone for arbitrary/self-hosted models, since naming conventions aren't consistent across hosts.
- Rationale: model-name string-matching cannot reliably identify provider for third-party-hosted models (inconsistent naming across hosts for the same underlying model). Explicit config always wins over inference to avoid silent misrouting or false "unsupported provider" failures.
- `TierConfig` gains two new optional fields: `provider` (explicit override) and `baseURL` (compatibility-endpoint routing). Both are dev-supplied, matching Axon's existing "dev owns their model config" posture.
- We just take name of the model and key and it is for dev to decide how we get it. he may keep a form for it to take model name which is not safe but a dropdown with all model names and baseURL for openai Compatible models already set by the dev.

### Model Selection: Dev-Owned, Not Axon's Concern

- Axon never determines how an end-user picks or types a model name. It only ever receives a fully-resolved tier config from the dev: `{ model, provider, baseURL?, apiKey }`.
- How the dev's app collects this from their own end-users a form field, a fixed dropdown with provider/baseURL pre-set per option or anything else is entirely the dev's implementation choice.
- A free-text field isn't a _security_ risk (still the dev's own key, own request). it's a _reliability_ risk: without paired `provider`/`baseURL`, Axon can't resolve the model and fails closed (`"unsupported provider"`). A dropdown is "safer" only in the sense that the dev pre-attaches correct provider/baseURL per option, guaranteeing resolvable config not in any security sense. Worth keeping these two distinct.
- Consistent with Axon's existing posture: no dashboard, no opinion on end-user-facing UI, no opinion on how failures are surfaced to the end-user (dev's Failure Handling responsibility, same as elsewhere).

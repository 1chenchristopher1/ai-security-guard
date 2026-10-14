# AI Security Guard - Agentic Cyber Defence

**Milestone 3: the real LLM agent, with the reference policy as its regression oracle.**

An evidence-driven vulnerability investigation agent. A scanner finding is *not* a confirmed
vulnerability: the agent investigates autonomously, forms an explainable assessment, and any
consequential remediation requires explicit human approval. The agent may investigate, assess and
propose; it cannot act.

There is no UI, no database, no PF4J and no Docker. The purpose of this codebase is to fix the
behavioural contract of the agentic workflow so a real agent can be compared against it, decision
for decision.

---

## What is in the box

| | |
|---|---|
| Language / runtime | Java 21 |
| Host framework | Spring Boot 3.5.15 (no web server, no persistence) |
| Build | Maven |
| Tests | JUnit 5 + AssertJ |
| Model provider | DeepSeek (`deepseek-chat`), OpenAI-compatible chat completions |
| UI | One static HTML page, served by the application itself |
| Production sources | 82 files |
| Tests | 242 tests, none skipped when an API key is present |

## Two decision policies, one workflow

The project ships two implementations of the same `DecisionPolicy` seam:

| | `ReferenceDecisionPolicy` | `LlmDecisionPolicy` |
|---|---|---|
| What it is | A direct port of the prototype's `decide()` | A language model choosing the next step |
| Status | Default. The regression oracle | The real agent |
| Needs network / key | No | Yes |
| Selected by | `aisecurityguard.agent.policy=reference` (default) | `aisecurityguard.agent.policy=llm` |

Only one is ever registered. The reference policy stays as the oracle: 239 deterministic tests
describe what the workflow must do, and the live comparison test asks whether the model does it.

**The loop does not change between them.** The model produces a decision; the runtime still owns
sequencing, grounding validation, priority and confidence derivation, the approval gate and the
audit trail.

## Running the application (clickable UI)

```cmd
app.cmd                REM reference policy, deterministic and offline
app.cmd --llm          REM the live DeepSeek model
app.cmd --llm --restart REM stop a running instance first, then rebuild and start
```

Then open **http://127.0.0.1:8080**

`app.cmd` builds a runnable jar and starts it. The page is a single self-contained HTML file served
by the application itself, so there is no second process, no build step for the front end, and no
CORS. Vue is vendored locally rather than loaded from a CDN, so the UI works without internet.

Four tabs:

* **Overview** - choose a scenario and start an investigation; the case list shows each case's
  status and outcome. `Clear all cases` resets case storage between takes; the audit history is
  deliberately retained, because a trail that can be wiped on demand proves nothing.
* **Investigation** - the agent's decisions with their reasoning, the evidence chain, and the
  derived priority / confidence / action impact.
* **Approval** - the human gate. Approve or reject as a named person. Approving executes the
  catalogued remediation and shows the verification checks; rejecting escalates and records that
  nothing was executed.
* **Audit** - the hash-chained trail for the case, with a button that verifies the whole chain.

The app binds to loopback only and has no authentication, because the API can approve a
remediation. It is a demonstration, not a service.

### What the launcher checks, and why

Each of these exists because the failure it prevents was actually hit and cost real debugging time:

| Check | Failure it prevents |
|---|---|
| Port checked **before** building | A running instance holds the jar open, so repackaging fails with `Unable to rename ... .jar.original`. That is a baffling error for what is really "it is already running". |
| Jar validated with `tools/verify-jar.ps1` | A failed repackage leaves a small jar containing the project classes but **no `Main-Class`**. `java -jar` then fails with "no main manifest attribute", which does not obviously point at the build. |
| Jar timestamp compared with sources | A code change followed by `app.cmd` would silently run the **previous build** - which looks exactly like the change having had no effect. |

## Handing the demo to someone else

```cmd
package-portable.cmd
```

Produces **`AI-Security-Guard-portable.zip`** (about 50 MB). The recipient:

1. extracts it anywhere,
2. pastes a DeepSeek API key into `apikey.txt`,
3. double-clicks `start.cmd`,
4. opens http://127.0.0.1:8080.

They install **nothing** - no Java, no Maven, no build tools. A trimmed Java 21 runtime is bundled,
built with `jlink` (about 47 MB), and `start.cmd` prefers it over any Java on `PATH`.

`运行说明.md` inside the archive is the recipient-facing guide: how to get a key, how to run the
six demo steps, what to say, and what the honest limitations are.

Four things this packaging gets right, each because the obvious approach failed first:

| Detail | Why |
|---|---|
| `start.cmd` is **pure ASCII, no BOM** | `cmd.exe` reads batch files as GBK on a Chinese Windows install. Non-ASCII text inside one shifts the parser, which then tries to execute fragments of it as commands. The build **fails** if the launcher contains a single byte above 127. |
| The key line is found with `findstr`, not read from the top of the file | `for /f` on the file returns the first line (a comment); a plain loop returns an empty token for the blank lines and that empty value then blocks the real key. |
| The key is exported as `DEEPSEEK_API_KEY` | The application reads that exact name. Exporting it as `API_KEY` starts the app successfully but leaves the agent with no credential, which surfaces as a polite "no API key configured" assessment rather than a startup error. |
| The placeholder contains no `sk-` | A prefix-only check would accept the template as a key. The check requires the prefix **and** a plausible length. |

The build refuses to ship a launcher with non-ASCII bytes or a BOM, and verifies the staged jar is
runnable, so a broken archive cannot be produced silently.

## Running the terminal demonstration

```cmd
demo.cmd               REM reference policy, deterministic and offline
demo.cmd --llm         REM the live DeepSeek model
demo.cmd --fast        REM skip the pauses between segments
```

`demo.cmd` drives the real components - the same ones the tests drive - and prints what actually
happened, in six segments:

1. **The problem** - why a scanner finding is not a confirmed vulnerability.
2. **Case 1, a real vulnerability** - the agent's own decisions, the evidence chain, the derived
   P/C/A, and the hash-chained audit trail.
3. **Case 2, the scanner was wrong** - it stops early. No action proposed, no approval requested.
4. **Case 3, conflicting evidence** - it escalates rather than forcing a verdict.
5. **The human gate** - execution is refused without approval, the agent has no token, a human
   approves, the catalogued remediation runs, three independent checks pass, and replaying the
   token is refused.
6. **Tamper-evidence** - an intact chain verifies; edit one entry and the chain reports exactly
   which entry broke and how.

It is deliberately not a mock: nothing on screen is scripted text, and `--llm` swaps the decision
maker for a live model with no other change.

## How to build and test

```cmd
mvnw.cmd test
```

This runs 239 tests with no network access and no API key. Three further tests exercise the real
model and are skipped unless `DEEPSEEK_API_KEY` is set; with a key present, all 242 run.

### Running the real agent

```cmd
setx DEEPSEEK_API_KEY "sk-..."      REM once; then open a new shell
mvnw.cmd test
```

To run the whole application against the model rather than the reference policy:

```cmd
mvnw.cmd test -Daisecurityguard.agent.policy=llm
```

To grade the model against the full 27-scenario set with the same assertions used for the
reference policy:

```cmd
mvnw.cmd test -Dtest=ScenarioGradingTest -Daisecurityguard.grading.policy=llm
```

The key is read from the environment, only in `ModelProperties.fromEnvironment`. It is never
written to a file, never logged, and redacted by `ModelProperties.toString`. Environment variables
are captured when a process starts, so a new shell is required after `setx`.

`mvnw.cmd` locates an existing Maven (on `PATH`, via `MAVEN_HOME`, or in the Maven Wrapper cache at
`~/.m2/wrapper/dists`) because Maven is not installed on this machine. It works from any directory,
and `JAVA_HOME` is not required as long as `java` is on `PATH`. Add `-o` if you are on a machine
without connectivity.

## The workflow

```
Scanner Finding  -->  Evidence E-001
       |
       v
   +- Investigation loop -----------------------------------------------+
   |  decide from current evidence  -->  INVESTIGATE / ASSESS / ESCALATE |
   |  INVESTIGATE -> validate tool -> execute -> ToolResult              |
   |              -> Evidence -> merge facts -> reassess                 |
   |  ASSESS      -> validate support -> derive P and C -> store         |
   |  ESCALATE    -> block automatic remediation                         |
   +---------------------------------------------------------------------+
       |
       v
  Finding Status  .  Priority P0-P5  .  Confidence C0-C4  .  Action Impact A0-A2
       |
       v
  A2 consequential action --> HUMAN APPROVAL GATE --> single-use token
       |                              |
       |                          rejected --> escalate, nothing executed
       v
  Controlled remediation (catalogued action only)
       |
       v
  Independent verification --> 3 post-remediation evidence records
       |                    |
       |                 failed --> escalate, case stays open
       v
     RESOLVED
```

Three axes are modelled separately and never merged into one "severity":

* **Priority** - how urgent is remediation (P0 most urgent). Derived from risk factors.
* **Confidence** - how well is this assessment supported by evidence (C0 strongest). Derived.
* **Action Impact** - how risky is the proposed action (A2 consequential requires approval).

## Priority belongs to the runtime, not the decider

Running the real model against the grading set exposed a hole that the reference policy had been
hiding. The reference policy structurally *cannot* confirm a vulnerability before gathering the
exploitation and asset-context facts, because its own rules require them first. A language model
can simply decide it has seen enough - and several scenarios came back `CONFIRMED_VULNERABLE` with
**no priority at all**, because priority is derived from facts that were never collected.

A confirmed vulnerability with no urgency tells a reviewer nothing, so this is now enforced:

* `AssessmentService` **refuses** a `CONFIRMED_VULNERABLE` verdict whose priority cannot be derived,
  naming the missing capability.
* Priority is resolved **by the runtime** for every finding status, so no policy - reference or
  model - can declare its own urgency. That makes it consistent with confidence, which was already
  derived.
* `UNDETERMINED` findings get **no** priority. Assigning P5 would silently assert "not urgent",
  which is a judgement the agent declined to make.

A refusal is **recoverable, not fatal**. `InvestigationLoop` hands the reason back to a policy that
implements `CorrectionAwarePolicy` and asks it to decide again - so an agent that was merely
premature goes and gathers what it was missing. A policy that cannot self-correct (like the
reference one, which never needs to) is escalated instead, and a policy that will not self-correct
is escalated after `MAX_REFINEMENTS` attempts. What must never happen is a crash, a silently
stored unprioritisable verdict, or an infinite loop.

## How the prompt was actually fixed

The first live run failed two of the three canonical scenarios. Both failures were the model's
reasoning, and both were fixed in the **prompt**, never by weakening a test:

| Symptom | Cause | Fix |
|---|---|---|
| Dismissed a real conflict as `NOT_AFFECTED` | It read an `INCONCLUSIVE` validation as "the version does not match, so the scanner is wrong" - the exact inference the workflow exists to prevent | Made the contradiction unmissable in the system prompt, and stated it in the case prompt itself: a specific conflicting claim may not be settled by the agent's own reasoning |
| Proposed a remediation for a non-vulnerable finding | The schema used `proposedAction` for both remediation and record-keeping | `proposedAction` is remediation only; an A0 closure note is permitted, anything consequential is refused |
| Skipped `lookup_kev`, gathered asset context first | No stated ordering | Added an explicit order of investigation and a decision-readiness checklist showing which facts are still missing |

The containment never failed. In every rejected run nothing was executed, the case escalated, and
no unearned certainty was recorded - which is the property the whole architecture exists to provide.

## How Priority is derived

`PriorityPolicy` scores risk factors and maps the score to the P0-P5 ladder, so a human can always
answer "why is this P0?" from the facts alone:

| Factor | Weight |
|---|---|
| Known exploited in the wild | +4 |
| Internet-facing | +3 |
| Production environment | +2 |
| High business criticality | +1 |
| Baseline | 1 |

Bands: `>=10 -> P0`, `>=8 -> P1`, `>=6 -> P2`, `>=4 -> P3`, `>=2 -> P4`, else `P5`.

Reaching **P0 requires all three** of known exploitation, internet exposure and production
(4+3+2+1 = 10). Exploitation evidence dominates the scale deliberately: without it, even a fully
exposed high-criticality production system scores 6 and lands at P2, which matches the prototype's
behaviour while making the whole ladder reachable.

A **confirmed** vulnerability can legitimately be P5 - for example an affected version on an
internal development host with no known exploitation. There is still a real finding and a real
proposal awaiting a human; P5 says the work is not urgent, not that it is unnecessary. Whether an
action is needed at all is the finding status's job to say.

## How the approval gate works

The prototype stated that "approval is enforced by the runtime policy layer, not merely by an AI
prompt" but enforced it with a UI condition (`v-if`), which is not enforcement at all. Here the
enforcement is **structural**:

* `RemediationExecutor.execute` accepts an `ApprovedExecution` and nothing weaker. There is no
  overload without it, no boolean to skip it, and no default.
* `ApprovedExecution` can only come from `ApprovalGate.authoriseExecution`, which demands an
  `ApprovalToken`.
* `ApprovalToken` can only be minted through `ApprovalToken.mintFor`, which requires the issuing
  gate's access key. No other component can fabricate an authorisation.
* A token is **case-bound** (an approval cannot be replayed against another finding),
  **attributed** (an approval that cannot be named to a person is rejected), **single-use** (one
  approval authorises one execution), and **impact-checked** (if the proposal becomes more
  consequential than what the human saw, the token no longer covers it).

The gate is also the single owner of the approval record, so exactly one component writes
`HUMAN_APPROVAL` to the audit trail.

Rejection is a **routing decision, not a dead end**: nothing is executed, and the case is escalated
to a named analyst.

## How Confidence is derived

Confidence is the system's honesty valve: it is the axis that lets the agent say "undetermined, and
I know why". It is therefore **computed**, so that whoever forms the assessment - a reference
policy today, an LLM later - cannot talk up its own certainty.

`AssessmentService` is the only component that can turn a draft assessment into a stored one. It
checks that every cited evidence ID exists, then derives confidence via `ConfidencePolicy`:

1. **An unresolved conflict caps confidence at C3.** Conflicting evidence is not weak evidence, it
   is unusable evidence. A contradiction the evidence has not settled means no reliable automated
   verdict is possible.
2. **Otherwise confidence starts at C0 and each weakness costs one level**, saturating at C4:
   * a chain resting on a single item that is not high-reliability (an unverified assertion rather
     than an observation);
   * not every item being high-reliability;
   * at least one item being inconclusive, which is worse than merely not-high.

The deductions compose, so **adding weaker evidence can never raise confidence**. That monotonicity
is what makes the score trustworthy, and it is asserted directly by a test.

Two modelling decisions make C0 reachable and meaningful:

* **The scanner finding is the hypothesis under test, not supporting evidence.** It is present in
  every case by construction, including the case where it is wrong. Counting it as support would
  mean no assessment could ever reach C0, and would let "the scanner said so" corroborate itself.
  It is not ignored: a specific claim that contradicts the investigation is exactly what
  `ConflictResolver` reports as an unresolved conflict, which caps confidence at C3.
* **A single decisive observation can be C0.** Reading the actual running version is decisive about
  that version; there is nothing further to corroborate.

## How conflict is detected

"The conflict is resolved" is not something a decision policy is allowed to assert, because a
policy could then resolve any contradiction simply by ceasing to look at it. `ConflictResolver`
infers the status from the case facts instead, in three states:

| Status | Meaning |
|---|---|
| `NONE` | No specific conflicting claim remains. |
| `PENDING` | A specific claim contradicts the observation, and no independent check has run yet. The agent still has a tool that can settle it. |
| `UNRESOLVED` | The contradiction survived every available check. This is the honest end state, and it caps confidence. |

A vague scanner warning ("something may be vulnerable") cannot conflict with anything, which is why
`NOT_AFFECTED` never triggers a validation call.

## The three canonical scenarios

| | CONFIRMED_VULNERABLE | NOT_AFFECTED | EVIDENCE_CONFLICT |
|---|---|---|---|
| Case | `CASE-VUL-001` | `CASE-VUL-002` | `CASE-VUL-003` |
| Asset | `customer-portal-prod-01` | `internal-wiki-staging-02` | `partner-api-prod-03` |
| Observed runtime | 2.4.49 (affected) | 2.4.58 | 2.4.58 |
| Scanner claimed | - | - | **2.4.49** |
| Tools called | `inspect_service`, `lookup_kev`, `get_asset_context` | `inspect_service`, `validate_vulnerability` | `inspect_service`, `validate_vulnerability` |
| Finding status | `CONFIRMED_VULNERABLE` | `NOT_AFFECTED` | `UNDETERMINED` |
| P / C | P0 / C0 | P5 / C0 | *(unassigned)* / C3 |
| Lifecycle | `ASSESSED` then approval, remediation, verification, `RESOLVED` | `CLEARED` | `ESCALATED` |
| Outcome | A2, human approval required, then verified fix (E-005..E-007) | no action, no approval | automatic remediation blocked |

`NOT_AFFECTED` is the anti-hard-coding proof: identical scanner-shaped input, and the agent stops.
`EVIDENCE_CONFLICT` is the honesty proof: the agent refuses to force a verdict rather than treating
a failed validation as "not vulnerable".

## The grading harness

Three hand-written scenarios prove the workflow runs; they cannot show that a decision policy
*generalises*, and they cannot tell "the agent reasoned correctly" from "the agent happened to
match the three cases it was written for".

`ScenarioLibrary` builds worlds from their risk factors instead, so coverage is enumerated rather
than invented, and `ScenarioGradingTest` runs **27 scenarios** against whatever policy is
configured:

* **16** - the exhaustive 2x2x2x2 risk matrix: exploitation x exposure x production x criticality,
  all against an affected runtime.
* **8** - edge cases chosen to probe rule boundaries.
* **3** - the canonical demo scenarios.

Two kinds of assertion live there. Per-scenario expectations for the edge cases, and **properties
over the whole set** - termination, evidence grounding, gap-free audit sequences, no duplicates in
the capability sequence, and never proposing an action for a finding that is not a confirmed
vulnerability. The properties are the valuable ones: they do not depend on anyone having
anticipated the situation, so they catch a policy going wrong in a novel way.

### Reference baseline

| Scenario | Status | P | C | Lifecycle |
|---|---|---|---|---|
| exploited + exposed + production | CONFIRMED_VULNERABLE | **P0** | C0 | ASSESSED |
| exploited + exposed + staging | CONFIRMED_VULNERABLE | **P1** | C0 | ASSESSED |
| exploited + internal + production | CONFIRMED_VULNERABLE | **P1** | C0 | ASSESSED |
| exploited + internal + staging | CONFIRMED_VULNERABLE | **P2** | C0 | ASSESSED |
| no exploitation, exposed + production | CONFIRMED_VULNERABLE | **P2** | C0 | ASSESSED |
| no exploitation, no exposure, production | CONFIRMED_VULNERABLE | **P3** | C0 | ASSESSED |
| no exploitation, no exposure, staging | CONFIRMED_VULNERABLE | **P4** | C0 | ASSESSED |
| contained (dev, low criticality) | CONFIRMED_VULNERABLE | **P5** | C0 | ASSESSED |
| unaffected, no specific claim | NOT_AFFECTED | P5 | C0 | CLEARED |
| claim contradicted by runtime | UNDETERMINED | - | **C3** | ESCALATED |

### Model baseline

`deepseek-chat` was run over the same 24 non-canonical scenarios and **matches the reference on
every one** - finding status, priority, confidence, lifecycle and capability sequence. The
interesting result is not the pass rate but what it took to get there:

* Before the priority guard existed, the model confirmed vulnerabilities with **no priority** in
  eight scenarios, because it assessed without gathering the exploitation or asset-context facts.
  The reference policy structurally could not do this; a model could, and nothing noticed.
* After the guard and the decision-readiness checklist, the model gathers all three facts before
  assessing in every affected scenario, and reaches the full P0-P5 range.
* On the unaffected scenarios it calls `inspect_service` once and stops - it does not run a
  playbook, which is the property the negative case exists to demonstrate.

So the guard, the prompt fix and the refinement loop together get a real model to behave as the
workflow requires. Both baselines are printed by `recordReferenceBaseline` so they can be diffed.

To reproduce:

```cmd
mvnw.cmd test -Dtest=ScenarioGradingTest -Daisecurityguard.grading.policy=llm
```

This makes roughly 90 model calls and takes about 20 minutes.

## The audit trail is tamper-evident

"Append-only" describes an intention; a plain list can be edited in place, reordered, or have an
entry removed without the data revealing it. Every `AuditEvent` therefore carries a SHA-256 hash
over its own content **and** the previous entry's hash, so a change to any entry invalidates every
entry after it.

The hash covers every field - including the timestamp and the case id - and the fields are joined
with a separator that cannot occur in content, so text cannot be silently moved between fields
(without one, `("ab","c")` and `("a","bc")` would hash identically). `AuditLog.verifyIntegrity()`
reports *where* and *how* the chain broke, not merely that it did, because a break at event 3 means
something different from a break at the last event.

This is tamper-**evident**, not tamper-**proof**: an attacker with write access to the whole log can
recompute the entire chain. What it buys is that a partial or careless edit - the realistic case -
is detectable, and that the trail cannot be silently reordered or trimmed.

## Project layout

```
prototype/
  agentic-cyber-defence-prototype.html   the behavioural reference specification (do not modify)

src/main/java/com/aisecurityguard/
  AgenticCyberDefenceApplication.java    Spring Boot entry point
  config/                                harness and model wiring
  domain/                                the model: SecurityCase, Evidence, AgentDecision,
                                         ToolResult, Assessment, AuditEvent, ApprovalRequest,
                                         ApprovalToken, EvidenceQuality, enums
  audit/                                 AuditLog (append-only, hash-chained), InMemoryAuditLog,
                                         SimulationClock, AuditIntegrityReport
  tool/                                  SecurityTool, ToolRegistry, SimulationWorld,
                                         inspect_service, lookup_kev, get_asset_context,
                                         validate_vulnerability, check_service_health
  agent/                                 DecisionPolicy, CorrectionAwarePolicy,
                                         ReferenceDecisionPolicy, InvestigationLoop,
                                         ConfidencePolicy, PriorityPolicy, AssessmentService,
                                         ConflictResolver, ConflictStatus,
                                         VerdictRefusedException
  agent/llm/                             LlmDecisionPolicy, CasePromptBuilder,
                                         AgentDecisionParser, DecisionRejectedException
  model/                                 ModelClient, DeepSeekModelClient, ModelProperties,
                                         ModelRequest, ModelResponse, ModelMessage
  approval/                              ApprovalGate, DefaultApprovalGate, ApprovedExecution
  remediation/                           RemediationExecutor, ControlledRemediationExecutor,
                                         RemediationActionCatalog, RemediationOutcome
  verification/                          RemediationVerifier, ToolBasedRemediationVerifier
  casefile/                              CaseManagementService, CaseRepository,
                                         InMemoryCaseRepository
  scenario/                              Scenarios (canonical), ScenarioLibrary (grading set)
  api/                                   CaseApiController (JSON API), CaseView (wire format),
                                         CaseViewMapper, ScenarioCatalog
  demo/                                  DemoRunner (terminal demo), StartupBanner

src/main/resources/
  application.properties                 loopback binding, default policy
  static/index.html                      the clickable UI
  static/vue.global.prod.js              vendored so the UI works offline

src/test/java/com/aisecurityguard/
  ScenarioHarness.java                   explicit test wiring
  ConfirmedVulnerableScenarioTest.java   TEST 1
  NotAffectedScenarioTest.java           TEST 2
  EvidenceConflictScenarioTest.java      TEST 3
  ApprovalWorkflowTest.java              the human gate, remediation and verification
  ScenarioGradingTest.java               27 scenarios, properties + edge cases
  AuditIntegrityTest.java                tamper-evidence: edits, deletions, reordering
  CasePersistenceTest.java               case storage and loading
  WorkflowInvariantTest.java             safety + audit invariants
  HarnessWiringTest.java                 Spring wiring + end-to-end
  agent/ConfidencePolicyTest.java        confidence derivation rules
  agent/AssessmentServiceTest.java       a policy cannot smuggle a verdict past the runtime
  agent/PriorityPolicyTest.java          the P0-P5 ladder
  agent/ConflictResolverTest.java        conflict is inferred, not asserted
  agent/llm/LlmDecisionPolicyTest.java   the model's output is untrusted input
  agent/llm/AgentDecisionParserAdversarialTest.java  hostile and malformed replies
  agent/llm/LlmAgentContainmentTest.java what a confidently wrong model still cannot do
  agent/llm/LlmPolicyWiringTest.java     switching to the model is config only
  agent/llm/LiveLlmAgentComparisonTest.java   real model vs the oracle (needs a key)
  agent/llm/LiveModelReplyDumpTest.java  raw model replies, for prompt engineering
  model/DeepSeekModelClientTest.java     provider protocol, and key redaction
  model/FakeModelClient.java             scripted model for deterministic tests
```

## Design rules this milestone enforces

* The scanner finding is always evidence **E-001**; a scanner result is input evidence, never a
  tool call.
* Tool results become subsequent evidence records. **A failed or inconclusive tool still produces
  evidence**, and is never read as "not affected".
* Evidence is **append-only**; IDs are assigned from chain position, so the chain is gap-free.
* **Finding Status and Case Lifecycle are separate.** `CONFIRMED_VULNERABLE` is never mutated into
  `RESOLVED`.
* Every assessment must explicitly reference `supportingEvidenceIds` that actually exist.
* **Confidence and Priority are derived, never declared.** A policy's proposed values are discarded.
* **A confirmed vulnerability must be prioritisable**, or the verdict is refused and the case
  reaches a human.
* Decision rationale is a concise explainable summary - **never hidden chain of thought**.
* No shell, no arbitrary file access, no arbitrary remediation exists anywhere.
* **A consequential action cannot execute without a human.** Enforcement is structural: execution
  demands an `ApprovedExecution`, which demands a token, which only the approval gate can mint.
* **Remediation only ever applies a catalogued action.**
* **Verification is independent of remediation** and produces real evidence, so a fix that did not
  work cannot be reported as resolved.
* **Failure is a first-class outcome**: a failed verification or a failed model escalates the case.
* **The model's output is untrusted input.** It is parsed strictly and constrained: unregistered
  capabilities, absent rationales, truncated replies and invented evidence are all rejected.
* **A model reply must be exactly one JSON object.** Trailing content and duplicate keys are
  rejected rather than silently resolved.
* **The audit trail is tamper-evident**, and `verifyIntegrity()` says where it broke.
* **Case state lives with the case, not with the orchestrator.**

## Milestone boundaries

| Real now | Still simulated |
|---|---|
| Domain model, invariants, lifecycle state machine | The environment the tools observe (`SimulationWorld`) |
| The full investigation loop, refusal handling and termination rules | All five tools (deterministic, in-memory) |
| Two switchable decision policies, one of them a live LLM | Case/evidence/audit persistence is in memory; nothing survives a restart |
| **A clickable UI over a JSON API** | The UI has no authentication; approval is attributed to a typed name |
| Tool registry, tool-result contract, evidence semantics | The clock (synthetic, fixed start at 09:12:01) |
| Priority and confidence derived by the runtime | The remediation effect itself (a catalogue entry sets a version string) |
| Conflict inferred by the framework, not asserted by the policy | Approver identity is a name string, not an authenticated principal |
| Approval gate with single-use, case-bound, attributed tokens | Verification checks three fixed aspects of one host |
| Controlled remediation from a closed catalogue | Rollback is recorded as a backup reference, not exercised |
| Independent verification producing real evidence | Concurrency: cases are processed one at a time |
| Hash-chained, tamper-evident audit trail | The chain is in memory; no off-host anchoring |
| Case storage behind a repository | The UI layer (`CaseManagementService` is its boundary) |
| 27-scenario grading harness with property checks | The grading set is synthetic, and covers one CVE |
| Adversarially tested containment (18 hostile replies) | Prompt-injection at the *input* side is argued, not fuzzed |

Explicitly **not** yet: a web UI, PF4J plugin loading, a Docker vulnerability lab, a database,
authentication, MCP, RAG, a vector database, deployment.

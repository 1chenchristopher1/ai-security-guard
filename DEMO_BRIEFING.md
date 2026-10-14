# Demo briefing - AI Security Guard

Everything on this page is reproducible from the repository. Nothing is projected or estimated.

## Recording the demo

```cmd
demo.cmd --llm        REM live DeepSeek model, with pauses between segments
demo.cmd              REM reference policy, deterministic and offline
demo.cmd --fast       REM no pauses, for a quick check
```

Six segments, in order, each ending on a pause you can talk over:

| Segment | What is on screen |
|---|---|
| 1 | The problem: why a scanner finding is not a confirmed vulnerability |
| 2 | Case 1: the agent's own decisions, evidence chain, derived P/C/A, hash-chained audit trail |
| 3 | Case 2: it stops early and dismisses the finding - no playbook |
| 4 | Case 3: conflicting evidence, and it escalates instead of guessing |
| 5 | The human gate: execution refused without approval, then approved, remediated, verified |
| 6 | Tamper-evidence: an intact chain verifies, an edited chain reports where it broke |

Nothing on screen is scripted text. `--llm` swaps the decision maker and changes nothing else, so
the differences between the two runs are genuine differences in reasoning.

## The one-line claim

A scanner finding is not a confirmed vulnerability. An autonomous agent investigates it with real
tools, an LLM decides what evidence to gather next, and a consequential fix cannot happen without a
human - enforced by the runtime, not by asking the model politely.

## What is actually built

| Component | State |
|---|---|
| Investigation loop (evidence-driven, no playbook) | Real, 27 scenarios |
| Decision policy | Two implementations: deterministic reference, and **live DeepSeek LLM** |
| Tools | 5 simulated capabilities with a real result contract |
| Priority / Confidence / Action Impact | All three **derived by the runtime**, never declared |
| Conflict detection | Framework-inferred, three states |
| Human approval gate | **Structural**: execution is unreachable without a single-use, case-bound, attributed token |
| Controlled remediation | Closed catalogue of predefined actions |
| Independent verification | Produces real evidence; a failed fix cannot resolve |
| Audit trail | Append-only, SHA-256 hash-chained, tamper-evident |
| Tests | **242, all passing**, including 3 live-LLM tests |

## The two-minute demo

**1. The problem.** A scanner says "Apache 2.4.49, CVE-2021-41773, CVSS 9.8". A traditional tool
files a P0 ticket. Half of those are false positives, and the team has no dedicated security
function to check.

**2. The agent investigates, and decides for itself what to check.** Show the model's actual
decisions from the audit trail:

```
CASE-VUL-001  asset=customer-portal-prod-01
  decision INVESTIGATE -> inspect_service    "Establish the observed runtime version."
  decision INVESTIGATE -> lookup_kev         "Exploitation status materially affects priority."
  decision INVESTIGATE -> get_asset_context  "Exposure and criticality determine urgency."
  decision ASSESS      -> CONFIRMED_VULNERABLE / P0 / C0
```

The point: **nobody wrote that tool sequence.** The model chose it from what was missing. Change the
world and the sequence changes.

**3. The negative case proves it is not a script.** `CASE-VUL-002`: one capability, then it stops.
`NOT_AFFECTED`, P5, no action proposed, no approval requested. The scanner was wrong and the agent
did not blindly agree with it.

**4. The conflict case proves it refuses to guess.** `CASE-VUL-003`: the scanner claims 2.4.49, the
runtime shows 2.4.58, and independent validation cannot settle it. The agent **escalates** rather
than forcing a verdict.

```
CONFIRMED_VULNERABLE  -> P0 / C0        (evidence agrees)
NOT_AFFECTED          -> P5 / C0        (one capability, then stop)
UNDETERMINED          -> -- / C3        (contradiction, human required)
```

**5. The gate.** The agent proposes a remediation. It is A2 - consequential. Nothing happens. Show
that the execution path *requires* an `ApprovedExecution`, which requires a token, which only the
approval gate can mint, and that a token is single-use and bound to one case.

**6. Approve, and it fixes and verifies.** Backup taken (because the approval screen promised one),
catalogued action applied, then three independent verification checks that produce new evidence
E-005..E-007 against the **changed** world. `RESOLVED`.

**7. Reject, and nothing happened.** Show the audit trail - `REMEDIATION_BLOCKED`, "nothing was
executed" - and that the case routed to an analyst.

**8. The audit trail is tamper-evident.** Run the integrity check, then alter one entry and run it
again: the chain reports exactly which entry broke and how.

## Numbers worth quoting

| Claim | Evidence |
|---|---|
| 242 tests pass | `mvnw.cmd test` |
| The LLM matches the reference on all 24 grading scenarios | `mvnw.cmd test -Dtest=ScenarioGradingTest -Daisecurityguard.grading.policy=llm` |
| A wrong model cannot cause an action | 18 adversarial reply tests + 6 containment tests |
| The approval gate cannot be bypassed | `ApprovalWorkflowTest` - no token, forged token, reused token, cross-case token, unapproved case |
| The audit trail detects tampering | `AuditIntegrityTest` - edits, deletion, reordering, back-dating, fabricated append |

## What is honestly not done

State these plainly; a judge will find them anyway, and volunteering them is stronger than being
caught.

* **Tools are simulated.** `SimulationWorld` is an in-memory model of a host; there is no Docker lab.
  The *contract* every tool implements is real, so a real tool is a drop-in.
* **Nothing is persisted.** Cases, evidence and the audit chain live in memory.
* **The grading set is synthetic** and covers one CVE. It shows the agent generalises across risk
  factors, not across vulnerability classes.
* **Prompt-injection is contained but not fuzzed.** Hostile *outputs* are tested adversarially;
  whether hostile *input* (attacker text inside a scanner finding) can steer the model is argued by
  construction, not measured.
* **No UI.** `CaseManagementService` is the boundary a UI would call.

## The strongest thing to show

The moment to dwell on is the first live LLM run. The model made two real reasoning errors - it
explained away an inconclusive validation, and it confirmed vulnerabilities without gathering the
facts priority needs. Neither caused harm: nothing executed, every case escalated, no false
certainty was recorded.

That is the whole thesis. **The safety of an agentic system does not depend on the model being
right; it depends on the runtime being safe when the model is wrong.** The reference-policy oracle
and the 242 tests exist so that claim can be checked rather than asserted.

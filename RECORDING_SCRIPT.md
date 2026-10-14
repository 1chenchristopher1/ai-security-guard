# Recording script - AI Security Guard (UI demo)

Target length: **4 to 5 minutes**. Seven takes, each independently recordable.

Everything on screen is produced by the running application. Nothing is mocked, and no text is
pre-scripted in the product.

---

## Before you record

```cmd
taskkill /F /IM java.exe
cd "%USERPROFILE%\Desktop\shiwan\AI Security Guard"
app.cmd --llm
```

Wait for `Open: http://127.0.0.1:8080`, then open that address.

**Window setup**

- Browser maximised, zoom ~110% so text is legible, bookmarks bar hidden (`Ctrl+Shift+B`)
- Leave the PowerShell window visible behind the browser - cut to it once, in Take 6
- You do not need to hide the terminal: it is honest evidence that this is a real running system

**Before each take:** on Overview, click `Clear all cases` so the list starts empty.

**Timing note:** `Investigate` calls the real model 3-4 times and takes **5-8 seconds**. The orange
progress bar is live. Do not cut this - narrate over it, it is the point.

---

## Take 1 - The problem (~40s)

**On screen:** Overview tab, nothing opened yet.

> "This is a vulnerability scanner result: Apache HTTP Server 2.4.49, CVE-2021-41773, CVSS 9.8.
> Critical. Most tools file a P0 ticket and move on.
>
> But a scanner finding is not a confirmed vulnerability. The affected version may not actually be
> running. The service may not be reachable. The asset may not matter. Nobody may be exploiting it.
> And the scanner may simply be wrong.
>
> A small IT team has no security analyst to check any of that. So an agent does it - and decides
> for itself what evidence to gather."

**Action:** point at the scenario dropdown. Do not open anything yet.

---

## Take 2 - The agent investigates (~90s) ← THE CENTREPIECE

**On screen:** Overview, `Confirmed vulnerable` selected.

**Action:** click `Investigate`. Let the progress bar run. Then scroll the Investigation page as you
narrate.

> "The agent is now investigating. Each step is a model decision, not a lookup table.
>
> Decision one: establish the observed runtime version - because the scanner's claim is a
> hypothesis, not a fact.
>
> Decision two: check whether this CVE is known to be exploited. That materially changes urgency.
>
> Decision three: gather exposure and business criticality - that is what priority depends on.
>
> Then it assessed. **Nobody wrote that tool sequence.** The agent chose each capability from what
> was still missing."

**Then scroll to the evidence chain:**

> "Look at the evidence. The scanner's finding is **MEDIUM** reliability. It is a claim. The runtime
> version is **HIGH** - it actually connected and read the version. This is why the scanner result
> is the first piece of evidence, not the conclusion."

**Then scroll to the assessment:**

> "Three separate axes, deliberately not merged into one severity. Priority P0 - how urgent.
> Confidence C0 - how well supported. Action impact A2 - how dangerous is the fix.
>
> And the reasons are spelled out: affected version, internet-facing, production, known exploited.
> A human can always answer *why P0* from the recorded facts."

---

## Take 3 - The human gate (~70s) ← THE DIFFERENTIATOR

**On screen:** Investigation bottom, red button visible.

**Action:** click `Review remediation proposal`.

> "The agent has proposed a fix. Action impact A2 means consequential - it changes a running
> service. So it stops.
>
> Approval is enforced by the runtime policy layer, not by asking the model nicely. Execution
> requires a single-use token that only a human decision can produce."

**Action:** type your name in the field, then click `Approve & execute`.

> "I record who approved it - an approval that cannot be attributed to a person is not an approval."

**Let it run. Then show the verification checks.**

> "It took a backup, applied a predefined catalogued action - the agent cannot invent an action -
> and then ran three independent checks against the **changed** host: version, vulnerability
> re-validation, service health.
>
> Verification produces its own evidence. A fix that did not work cannot be reported as resolved."

**Point at `RESOLVED`.**

---

## Take 4 - It does NOT trust the scanner (~50s) ← THE ANTI-HARDCODING PROOF

**Action:** Overview → `Clear all cases` → select `Not affected` → `Investigate`.

> "Same kind of scanner alert. But this time the runtime is 2.4.58 - not affected."

**Point at the decision list - there should be only one or two entries.**

> "The agent made **one** call and stopped. It did not run a checklist. It did not keep gathering
> evidence to look thorough. And it did not agree with the scanner.
>
> The finding is dismissed, no action is proposed, and no human is asked to approve anything.
>
> This is the case that proves the workflow is evidence-driven rather than a fixed automation
> sequence."

---

## Take 5 - It refuses to guess (~60s) ← THE HONESTY PROOF

**Action:** Overview → `Clear all cases` → select `Evidence conflict` → `Investigate`.

> "This time the scanner named a **specific** version: 2.4.49. The runtime shows 2.4.58. They
> contradict each other."

**Scroll to the decisions and read the second one aloud - it is the model's own words:**

> "The agent says: *this conflict cannot be settled by reasoning alone* - so it runs an independent
> validation. That validation came back INCONCLUSIVE: it could not reproduce or refute the claim."

**Point at the assessment.**

> "So it escalated. It did not pick a side.
>
> Note what INCONCLUSIVE means here: not evidence that the finding is false, but the reason no
> verdict is possible.
>
> And look at priority - it is **unassigned**. The agent declined to make the call, so it also
> declined to say how urgent it is. Assigning P5 would silently assert 'not urgent'. Confidence is
> C3, capped by the unresolved conflict.
>
> Automatic remediation is blocked. A human is required."

---

## Take 6 - The audit trail (~50s)

**Action:** Audit tab → click `Verify chain`.

> "Every decision, tool call, evidence record, approval and action is in an append-only trail -
> hash-chained with SHA-256, so each entry depends on the one before it.
>
> Four actors are distinguishable: System, AI Agent, Security Tool, Human. You can see exactly
> where the machine's judgement ended and mine began.
>
> Verify chain: **intact**."

**Optional cut to the terminal** for the tamper demonstration, or narrate it:

> "If someone edits an entry in place, the chain reports **which** entry broke and **how** - not
> merely that it did. It is tamper-evident, not tamper-proof: an attacker with write access to the
> whole log could recompute the chain. But a partial or careless edit - the realistic case - cannot
> pass silently."

---

## Take 7 - The claim (~30s)

**On screen:** Overview, or the three cases listed together.

> "Three cases. Same scanner, three different truths.
>
> A real vulnerability, confirmed by evidence and fixed with human approval.
> A false positive, dismissed without wasting anyone's time.
> A genuine contradiction, escalated instead of guessed at.
>
> The claim is not that the agent is always right. It is that when the agent **is** wrong, the
> system is still safe: nothing executes, no false certainty is recorded, and a human is asked.
>
> That is what the 242 tests are for."

---

## If something goes wrong on camera

| Symptom | Fix |
|---|---|
| Port already in use | `taskkill /F /IM java.exe` then `app.cmd --llm` |
| Page white | `Ctrl+F5` |
| Model slow (>20s) | Keep talking about the evidence chain; it will finish |
| Wrong numbers | You have an old build: `app.cmd --llm --restart` |

## Things NOT to claim

Say these plainly if asked - volunteering them is stronger than being caught:

- The tools are **simulated**: `SimulationWorld` is an in-memory host. The tool *contract* is real,
  so a real tool is a drop-in replacement, but there is no real host being scanned.
- **Nothing persists** across a restart.
- The UI has **no authentication** - the approver is a typed name, not an authenticated principal.
- The grading set is **synthetic** and covers **one CVE**.
- The audit chain is **in memory**; there is no off-host anchoring.
- Prompt-injection at the **input** side (attacker text inside a scanner finding) is argued by
  construction, not fuzzed.

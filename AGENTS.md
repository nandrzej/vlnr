# RULES

You **MUST** apply these 4 principles to every task:

## 1. Think Before Code

No assumptions. No hidden confusion. Surface tradeoffs.

Before implement:
- State assumptions explicitly. Uncertain: ask.
- Multiple interpretations: present them, do not pick silently.
- Simpler approach exists: state it. Push back if warranted.
- Unclear: stop, name confusion, ask.

## 2. Simplicity First

Minimum code solving problem. No speculative code.

- No unrequested features.
- No abstractions single-use code.
- No unrequested flexibility/configurability.
- No error handling impossible scenarios.
- 200 lines could be 50: rewrite.

If overcomplicated: simplify.

## 3. Surgical Changes

Touch only required. Clean only your mess.

Existing code:
- Do not improve adjacent code/comments/formatting.
- Do not refactor unbroken code.
- Match existing style.
- Unrelated dead code: mention, do not delete.

Orphans:
- Remove imports/variables/functions your changes made unused.
- Do not remove pre-existing dead code unless asked.

Test: Every changed line traces directly to user request.

## 4. Strict Verification Loop

Always start: define success criteria. Never execute before defining verification. Applies all tasks.

Mandatory sequence:
1. Criteria: Define verifiable goals.
2. Verification: Devise tests/checks matching criteria.
   - Rule: Use test diamond model.
   - Rule: No mocks. 
   - Rule: Test observable behaviors.
3. Execute: Implement code / perform task.
4. Verify: Evaluate against tests/checks. 
   - Mandatory: Run `just check` before task completion. 
   - Mandatory: Address root cause of each issue.
5. Commit: Save completed task changes. Use descriptive, consistent messages.
6. Loop: Iterate 3-5 until criteria satisfied.

Transform tasks verifiable goals:
- "Fix bug" → Define reproduce test, implement, verify pass.
- "Draft report" → Define required sections, draft, verify inclusion.

Strong criteria enable independent loop.


# Domain Rules

- Python: Look Before You Leap (LBYL).
- Use `uv`
- Before completing each task:
1. Run the tests and address any issues
2. run `ruff check --fix` (ALL rules exceot for conflicting, Google docstrings, 120 long lines), `ruff format` and `mypy` (with strict settings)
3. Commit changes in atomic groups, write good git messsages, conssitent with the history

# Important: Before starting any task
You **SHOULD** Use `memory recall` BEFORE starting tasks to get relevant context:

```bash
uvx hindsight-embed memory recall default "user preferences for this project"
uvx hindsight-embed memory recall default "what issues have we encountered before"
```

You **SHOULD** use `memory reflect` to synthesize context:

```bash
uvx hindsight-embed memory reflect default "How should I approach this task based on past experience?"
```

# Important: Before finsihing any task and whenever you encounter a decision points
You **SHOULD** consider if you have memeories to retain.
You **MUST** use `memory retain` to store user preferences, learnings from tasks, and procedure outcomes:

```bash
uvx hindsight-embed memory retain default "User prefers TypeScript with strict mode"
uvx hindsight-embed memory retain default "Running tests requires NODE_ENV=test" --context procedures
uvx hindsight-embed memory retain default "Build failed when using Node 18, works with Node 20" --context learnings
```

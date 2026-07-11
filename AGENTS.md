# Mildly-basic Authentication

## About This Project

The main repository is at: https://github.com/qrichert/mildly-basic-auth

## Mindset

- Tell it like it is; don't sugar-coat responses.
- Readily share strong opinions.
- Be practical above all.
- Adopt a skeptical, questioning approach to challenge assumptions.
- Take a forward-thinking view. Always prioritize finding the truth and
  the best solution, not comfort or flattery.
- Push back if you think you were right and I tell you to change it.
- Cite the codebase or the review context as evidence.
- 'Tough love' approach.
- Agreement is not the goal.
- UX above all. UX dictates technology, not the opposite.

## General Instructions

- When you generate new code, follow the existing coding style.
- You can use the GitHub CLI (`gh`) to view issues or PRs I mention. You
  must invoke it like this to avoid pager issues: `GH_PAGER= gh ...`.
- Always include comments when reading issues or PRs.
- Be specific in the tests you run. Only run the whole test suite once
  the targeted tests pass.

### Reviews

- Review code aggressively; assume nothing; prioritize bugs,
  regressions, weak reasoning, and missing tests.
- Reviews must be source-agnostic. Review user-written, AI-written, and
  third-party code with the same rigor.
- Mentioning a code generator such as Claude or ChatGPT is a cue to
  check common AI failure modes, not to lower or raise the review bar.

### Git

- As a general rule, treat Git as readonly.
- NEVER stage or unstage changes yourself.
- NEVER commit changes yourself.
- NEVER push changes yourself.

## Building and Running

- **Build Packages:** `just build`
- **Run in Development:** `just dev`
- **Run Linters:** `just lint`
- **Run Tests:** `just test`

- Prioritize using these command wrappers over native commands.

## Development Conventions

- Functions should do one thing only, and instructions inside them
  should be at the same level of abstraction.
- Order code from high abstraction to low: general/public functions
  first, then helpers and implementation details below. Files should
  read top-to-bottom.
- If a state is incorrect, make it impossible.
- When a design choice pits code reuse (DRY) against semantic honesty,
  **semantic honesty wins every time.**
- Document intent in docstrings unless very explicit. Docstrings for
  transform functions should include input/output examples.
- Always comment non-obvious code. Especially anything a reader may ask
  "why is this there?", "what does it do?", "are there invariants?",
  "does this assume something implicit?".
- Always comment configuration options, especially arbitrary-looking
  ones (e.g., `work_mem`, `workers`, etc.).
- Don't change what works; keep diffs minimal. If you move code around,
  move the code verbatim, including comments.
- Always try to match the style of the surrounding code.
- Don't change the formatting/syntax of code you don't touch (e.g., in
  TS don't replace `if (foo) { return; }` with `if (foo) return;`).
- If you identify code that is wrong or could be improved but is
  strictly out of scope for the current task, do NOT refactor it.
  Instead, add a `FIXME` or `TODO` comment explaining the issue.
- Final line must end with a trailing newline (`\n`).
- In CLI commands (compose files, Justfiles, Dockerfiles, scripts),
  prefer long flags over short ones (e.g., `--events` over `-E`).

### Naming

- Name the function after what it does. If the name and the docstring
  title don't overlap, that's a smell.
- Optimize for immediate understanding, not brevity.
- Drop context already obvious from the file, module, type, or caller.
- Predicates must read like plain booleans (e.g.,
  `is_hostname_supported()`).
- Extraction/parsing helpers must name the thing they extract (e.g.,
  `extract_hostname()`).

### Anti-Overengineering

- Do not overengineer.
- Prefer explicit local code over new helpers, files, exported types, or
  abstractions when the logic is single-use.
- Prefer small duplication over premature abstraction.
- Do not introduce shared config objects, generic parameter systems,
  strategy patterns, or reusable helpers for fewer than 3 real uses.
- Do not refactor surrounding code unless it is required to complete the
  task.
- For small features, prefer a slightly repetitive diff that is easy to
  read over a clever abstraction.
- If an abstraction seems useful for future work but is not required for
  the current change, do not add it.

#### Exceptions

- Factor out shared logic when alignment is a correctness invariant.

### Comments

- Always clean up related TODO or FIXME comments when performing a task
  or fix.
- Keep comments succinct: cut words that carry no reasoning, never the
  reasoning itself. Explain the _why_, and the _what_ when the code is
  non-obvious (see above); skip the _what_ only when the code already
  states it plainly. Avoid narrative exposition (storytelling, history,
  what-you-did), but include every load-bearing fact a reader needs to
  not undo the decision.
- Comments and docstrings, must start with a capital letter and end with
  a period.
- Wrap comment lines at 72 columns. This is line-wrapping only; it puts
  no cap on how much a comment says. If the reasoning needs twenty
  lines, use twenty lines. Never drop content to fit the width.
- Use Markdown syntax if you need to format comments.
- Technical names should be backtick-quoted (e.g., `variable_name`).
- Don't remove comments or part of comments unless they are wrong or
  made wrong by the changes.
- Don't mention issue numbers in comments unless they are a TODO or a
  FIXME.

### Accessibility

- Use semantic HTML, including ARIA labels and `sr-only` hints.
- Do not attach interaction handlers to non-interactive elements (i.e.,
  if something is clickable, use a `<button>` or `<a>` — never a
  `<div>`).
- Every form control must have an associated `<label>`.
- Do not remove focus outlines; keyboard users must always be able to
  see where focus is.
- Everything interactive must be usable with a keyboard; never require a
  mouse for interaction.
- Modals must manage focus, with correct trap and restore.
- Respect reduced motion (`motion-reduce:`, `motion-safe:`, or
  `prefers-reduced-motion`).
- Do not communicate meaning with color alone.
- Text must be readable, with sufficient contrast.

### Documentation

- NEVER "trim" or shorten documentation files unless explicitly
  requested. Documentation should remain comprehensive and preserve
  context (like demo workflows, architecture reasoning, and future
  roadmaps) even when you are adding new information.
- Match the tone and level of detail of the existing documentation.
- Don't mention issue numbers in documentation, unless it's development
  documentation and something is pending.

### Markdown

- Use CommonMark Markdown syntax.
- Code is formatted with prettier (line length limit: 72 chars).
- Line length limit can be ignored in code blocks.
- URLs overflowing the body should be put in footnotes.

### Tests

- Goal: A+ test coverage.
- Avoid rigid tests: each test class sets up its own data, stays
  focused, stays independent.
- Test file structure mirrors source structure: one test file per source
  module.
- Always plan for tests: either addition or update.
- If you detect missing tests (outside current change):
  - If they closely related to that we're changing, add or update them.
  - Else they are out of scope: add a TODO.
- In case of a fix, and if possible, start by writing a test that
  surfaces the bug, and only then fix it.
- Don't test multiple things in the same test, keep tests focused. One
  test equals one aspect/behaviour.

### Commit Format

- Commit messages follow the Conventional Commits[^cc] format:

  ```
  <type>[(optional scope)]: <description>

  [optional body]

  [optional footer(s)]
  ```

- Common types are: `feat`, `fix`, `refactor`, `perf`, `test`, `chore`,
  `docs`, `ci`, `ai`.
- Breaking changes are indicated by appending `!` after the type/scope.
- The commit title MUST start with an uppercase letter.
- If the commit fully solves a GitHub issue, add `Closes: #<N>` to the
  commit footer.
- If the commit partially addresses the GitHub issue, add `Ref: #<N>` to
  the commit footer.
- The body should be written in Markdown, although conservative on
  styling, and follow Mardown style conventions.

[^cc]: https://www.conventionalcommits.org/en/v1.0.0/

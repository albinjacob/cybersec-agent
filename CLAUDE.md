# Project instructions

## Keep `docs/architecture.html` in sync — no need to ask first

`docs/architecture.html` is a visual system diagram (as-built vs. roadmap),
linked from `README.md`. Whenever a commit changes what the system actually
does — a new agent, a new external integration, a pipeline stage added or
removed, a feature moving from mock/roadmap to real/shipped (or the
reverse), a path/filename a box's `<span class="tag">` references — update
the corresponding box(es) in the same commit:

- New capability shipped → add or flip its box from `.box.road` to
  `.box.done`.
- Capability removed or descoped → remove its box, or flip it back to
  `.box.road` if it's still a real future direction.
- A referenced path/filename changes → update the `<span class="tag">`
  text to match.

Don't wait to be asked — treat this the same as updating a docstring next
to code you just changed. If a change doesn't affect anything the diagram
depicts (e.g. a pure refactor, a test, a doc wording tweak), no update is
needed.

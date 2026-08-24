# Agent Guidelines

## Git Workflow

- Commit and push changes directly to `main` unless the user explicitly asks
  for a branch, pull request, or other workflow.
- Never delete, force-push, or reset any branch (including `main`) unless the
  user explicitly asks for that specific action in that message.
- Never run destructive git operations (`git reset --hard`, `git push --force`,
  `git branch -D`, deleting remote branches/refs, etc.) without explicit,
  unambiguous user confirmation for that exact operation.

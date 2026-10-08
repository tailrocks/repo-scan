# Authorized remote (2026-10-07)

Owner explicitly authorized creation + push in-session.

- Remote: `origin` → `git@github.com:tailrocks/repo-scan.git`
- Branch: `work/fast-complete-scan` (tracks `origin/work/fast-complete-scan`).
- Policy: all goal implementation commits on this one work branch; push
  at once after each commit (`git push`, no force). Implementation changes
  only; the scanner never commits or pushes inside examined repositories.
- Git writer: the coordinator session only. Subagents hand off file
  contents + checks; the writer applies, commits (`git commit -s`), pushes.

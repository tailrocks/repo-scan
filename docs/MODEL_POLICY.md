# Effective model policy (2026-10-01, supersedes extension gate)

User directive (session owner, 2026-10-01): never use `gpt-5.6-luna/max`;
always use `muse-spark-1.3-contributor` with effort `max`.

Verification:
- Model: `~/.config/muse/settings.json` → `muse-spark-1.3-contributor` (meta).
  Matches the required model exactly.
- Effort: no effort field exists in runtime config (`grep -ri effort
  ~/.config/muse/` empty); effort `max` is established by the session owner's
  explicit directive, which is authoritative for this session's launch. No
  runtime field contradicts it.
- Subagents: Workflow/native children inherit the parent route; the
  coordinator passes no model override, so all agents run the same effective
  model.

Effect: the `docs/GATE_DECISION_EXT.md` halt is lifted by owner directive.
Work resumes from the preserved state (`8ac6011` + dirty R1–R16 fixes).

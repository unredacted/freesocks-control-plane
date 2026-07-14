# Translation review packets

Per-locale review documents for native speakers, generated from the live
message catalogs by `bun run i18n:review` (`scripts/i18n-review-packet.ts`).

- One file per locale (`fa.md`, `ar.md`, `ru.md`, `zh.md`): every UI string
  grouped by feature, English source beside the current translation, with
  ⚠️ **MISSING** marking strings that still fall back to English in the app.
- Each file opens with reviewer instructions (what to keep untranslated,
  placeholder rules, tone guidance for an at-risk audience).
- Reviewers can edit the files directly (PRs welcome) or send corrections any
  other way; the operator applies them to `messages/<locale>.json` and re-runs
  the generator to refresh these packets.

These files are generated — don't hand-edit them expecting the app to change;
the source of truth is `messages/*.json`.

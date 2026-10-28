# Analyze native publication next wave

This local candidate selectively applies the qualified runtime changes from
`codex-opt-analyze-native-20261028` onto public main `ec306486`: publication
inventory is prepared only when needed; unchanged final artifacts, Markdown
inventory and expanded graphs are reused under exact signatures; bounded JSON
preparation and Markdown spool writes are batched. Priorities is skipped only
when saved finding and review evidence supports no action candidate. The held
AWS checkpoint change and scanner fanout are excluded.

The source branch's saved bf67 replay produced identical full Markdown bytes
for the reuse and batching paths. The final publication reverse pair saved
6.894–12.384 process CPU seconds and 10.536–18.434 wall seconds locally;
the large Markdown spool reverse pair saved 1.170–2.497 process CPU seconds.
These runs used a local artifact adapter and no real S3 calls. The no-action
Priorities gate was exercised against a saved Azure report with zero supported
actions and no model invocation. The original evidence and limits are in
`docs/performance/aws-bf67-analyze-native2-20261028.md` and
`docs/performance/azure-f95a7c9a-analyze-fixed-overhead-20261028.md` on the
source branch.

The d565 production Analyze baseline was 908.402 seconds by stage timestamps.
`worker.ai` used 615.739 seconds of wall time, and two final publications
used 220.411 seconds; their nested S3 puts used 200.938 additive SDK seconds.
The candidate addresses a portion of publication time. Local replay results
are projections for production: hosted Analyze wall, CPU, RSS, artifact
parity and cost still need measurement. The source branch did not establish
a new d565 production time.

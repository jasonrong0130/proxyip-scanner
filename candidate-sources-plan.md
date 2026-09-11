# Public Candidate Sources rollout

This feature branch adds a candidate-source console that only consumes publicly listed ProxyIP sources and submits candidates to the existing Scanner job API for the already-validated EDT runtime probe.

Rollout order:
1. Validate HTML/JavaScript and existing Scanner imports in CI.
2. Deploy the feature branch to the RackNerd Scanner VPS only.
3. Test candidate acquisition for HK first with a small limit.
4. Confirm known-good and known-bad samples are still classified correctly by EDT runtime validation.
5. Only after live validation, decide whether to merge to main.

The production `main` branch is intentionally unchanged during this test phase.

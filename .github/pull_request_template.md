## Summary

- What changed?
- Why is it needed?

## Validation

- [ ] `ruff check rulescope tests`
- [ ] `pytest`
- [ ] `rulescope scan examples/rules --top-issues 5`
- [ ] `rulescope compare baseline candidate --fail-on-regression` (if detection content changed)

## Detection Content Impact

- [ ] No rule semantics changed
- [ ] Rule semantics changed and were reviewed
- [ ] ATT&CK mapping reviewed
- [ ] False positives / analyst notes reviewed

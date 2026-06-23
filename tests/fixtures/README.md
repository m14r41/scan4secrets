# Test fixtures

Drop sample files here that contain known-format secrets (use clearly-fake but realistic values) and look-alike non-secrets. Add a paired pytest case in `tests/test_rules.py` that asserts the matching rule fires on the secret and does NOT fire on the look-alike.

Naming convention:
- `tp_<rule_id>.txt` — true-positive fixture for a single rule
- `fp_<short_label>.txt` — false-positive fixture (a known look-alike pattern)

Never commit a real, live credential. Generate look-alike values by hand or with a CSPRNG.

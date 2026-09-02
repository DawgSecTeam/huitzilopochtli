# Huitzilopochtli – Current Status

## Known Issues / Remaining Work

### Acceptable / Non-blocking
1. **Pure-Python Ed25519 performance** – each sign/verify takes ~2s. Loopback tests need 10-12s sleep windows. Not a correctness issue; acceptable for v1. Consider switching to `cryptography` library Ed25519 for production.

All previously reported correctness bugs are fixed and merged. No open blocking issues.

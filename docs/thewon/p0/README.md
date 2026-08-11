# TheWon P0 R8 Candidate Contract

R8 is an offline, `QUARANTINED_NO_DEPLOY` candidate based directly on Base
Authority Record `af37881b93a393cfe0ee24666709af0fcbda6109`. It is not a
runtime change, a Gatekeeper packet, or a standing-GV approval.

A valid roundtrip requires one human-origin request, one non-empty MINA
terminal reply with exact metadata, a tool artifact, a strict Workflow artifact,
and a strict Blackbox event. The Blackbox event is re-read, byte-hashed, joined
by `event_id` to the real producer `durable_receipts` schema, and matched
against the durable row, both JSONL projections, and their event identities.
Health, spinner, envelope hash, or a receipt string is never sufficient.

The manifest, ledger mutation boundary, acquired/released leases, and actual Git
diff must be exactly the same path set, including the ledger. The external scope
report contains the candidate commit/tree and its own report hash; no candidate
artifact contains a self hash.

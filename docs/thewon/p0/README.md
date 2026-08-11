# TheWon P0 R7 Candidate Contract

R7 is an offline, `QUARANTINED_NO_DEPLOY` candidate based directly on Base
Authority Record `af37881b93a393cfe0ee24666709af0fcbda6109`. It is not a
runtime change, a Gatekeeper packet, or a standing-GV approval.

The verifier permits a roundtrip only when one human-origin request has one
non-empty MINA terminal reply with exact metadata, a tool artifact, a strict
Workflow artifact, and a strict Blackbox event joined to its read-only SQLite
durable receipt. Every producer artifact is re-read and hashed at validation
time. A response count, spinner, health status, envelope hash, or receipt
string is never sufficient evidence.

The manifest, ledger lease boundary, and actual Git diff must be the identical
set of paths. The external scope report contains the candidate commit/tree and
its own report hash; neither ledger nor manifest contains a self hash.

# TheWon P0 Evidence Control Plane

This directory is the Git-tracked authority for P0 issue state, mutation leases,
and evidence transitions. Slack and Vault/Obsidian records must link to a ledger
event and source hashes; neither is authoritative by itself.

Historical files `PhaseC_Roundtrip_Evidence_20260811.md` and
`PhaseD_Plan_20260811.md` in the Vault are superseded as completion evidence.
They are retained for provenance, but cannot close P0 because they used reply
counts and did not bind a standing GV review to a requested run.

Every live change begins with an issue, a valid resource lease, a pre-state
digest, a rollback command, and a candidate commit. Completion requires the
producer packet, a standing GV verdict, MINA's decision, and a Codex teacher
review whose source pointers are recorded in the ledger.

## R1 Candidate Provenance

The original `b27d824a3` candidate is retained only as historical evidence. Its
declared base (`1811e42c`) was not the currently selected TheWon source target,
so its `audit_ready` transition cannot be used for deployment.

The R1 candidate is recreated in the isolated worktree
`/Users/elroy/.hermes/worktrees/thewon-p0-evidence-plane-fork-20260811` from
`Elroykim/hermes-agent` `fork/main` at
`053e585ae3e79ce00104cf688c7eba48a77cc8bf`. The active policy anchor is
`/Users/elroy/.hermes/memories/MEMORY.md` with SHA-256
`e52ab9c83ba88bfaf61fe9b705fd51b299a6b44b3101408354f2cb3677ebdca4`.

That anchor is an active runtime policy file rather than a Git object. It is
therefore sufficient to recreate a candidate, but it is not a release approval:
standing GV must confirm the repository, remote, and base before a Gatekeeper
packet can be issued. Until then, this candidate is
`CANDIDATE_RECREATED_UNREVIEWED` and all live mutation remains prohibited.

The prior ledger is preserved at
`docs/thewon/p0/history/legacy-evidence-ledger-b27.json`. It is superseded as
completion evidence, not erased. The current ledger and candidate manifest
must bind only the recreated worktree's artifacts, snapshot, and exact base.
R2 is a separate candidate recreated under Vault bootstrap lease lease-282df4d1-bb38-486a-bcc9-6d210c719331, committed in Vault receipt 283c5b0a0cb04414b535a313b933ffd236f893a3.
R1 remains REWORK evidence because its dependency repair occurred after its local lease was released.
R2 is candidate-only and requires standing GV review, MINA final evidence recheck, and a Gatekeeper packet before any live action.

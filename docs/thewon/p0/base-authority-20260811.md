# TheWon P0 Base Authority Record - 2026-08-11

## Selection

- Selected repository remote: `fork` (`https://github.com/Elroykim/hermes-agent.git`)
- Selected ref: `fork/main`
- Selected base commit: `053e585ae3e79ce00104cf688c7eba48a77cc8bf`
- Selected base tree: `6950f060c82073640e7f7a28f3ff2845737f258c`
- Owner-plan source: https://the-won-hq.slack.com/archives/C0BLPP2N6BX/p1786456424860439?thread_ts=1785382723.729409&cid=C0BLPP2N6BX

This record selects only the Git base for a new TheWon P0 candidate rebuild. The selection is an
owner-directed governance decision, not a signature, release, deployment, or runtime-authority
claim.

## History Boundary

At recording time, the local clone reports itself shallow. In the available history,
`origin/main` (`c0106e50e7ecedb3ce34e785d949725dc4e0e457`) and `fork/main`
(`053e585ae3e79ce00104cf688c7eba48a77cc8bf`) have no merge base, and the available divergence
count is `1 3383` for `origin/main...fork/main`. Therefore neither ref is treated as an inferred
ancestor of the other. This is a local shallow-history observation, not a claim about complete
remote history.

R2 and R3 candidates are excluded from this authority selection. In particular, R3 remains
`REWORK / QUARANTINED_NO_DEPLOY`; it is not a release base, Gatekeeper input, or live deployment
authority.

## Authorized Next Gate

This record authorizes only a fresh, isolated R4 candidate worktree from the selected base. The
R4 candidate must bind its complete effective Git diff to an exact resource lease, record
pre/post provenance, and pass an independent audit before any subsequent Gatekeeper consideration.

This record explicitly does **not** authorize release, Gatekeeper approval, deployment, restart,
service/runtime mutation, or any other live mutation.

# TheWon P0 Evidence Plane R6

R6 is a candidate-only, offline verifier. It never posts to Slack, changes a
runtime, starts a service, or treats process health as completion evidence.

The candidate base is Base Authority Record commit
`af37881b93a393cfe0ee24666709af0fcbda6109`, whose commit tree is
`4b9cbdf2c96d29afb8241ba61efb56a669acc3d2`. Its parent candidate rebuild base
is `053e585ae3e79ce00104cf688c7eba48a77cc8bf`, whose tree is
`6950f060c82073640e7f7a28f3ff2845737f258c`. These are distinct values.

Before a live Gatekeeper action, the complete sequence remains producer packet,
standing named GV review, MINA final evidence decision, and Codex teacher
review. Slack and Vault are evidence mirrors with source pointers; Git is the
candidate authority.

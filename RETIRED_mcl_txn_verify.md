# RETIRED — `mcl_txn_verify.cpp` / `results/mcl_txn_verify.txt`

This program implements the **superseded input-composition form** of the Paper-5 transaction tag
(`Tag = MCL(hash(TX) ⊕ N(c), p_device, q_device)`), whose 64-bit engine-input fold binds the transaction to
only 64 bits. Its banner still says "Paper 5 §V.A, Eq. 3"; that is **no longer the protocol of Paper 5**.
The current protocol (transaction, counter and device secret entering the twelve-weight derivation; Eqs. (3a)–(3))
is implemented by `p5_hardened_txauth/mcl_txauth_v3_battery*.cpp` (harness v3.2). The file and its record are kept
only as the historical source of the measurements they produced (2026-06). Do not cite them for Paper 5's claims.

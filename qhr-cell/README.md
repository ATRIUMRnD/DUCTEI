# qhr-cell and qhr-sched

QHR (Quantum Hybrid Runtime) is the hyper driver's speculative scheduler,
built as two DUCTEI workspace crates. The quantum vocabulary is a design
metaphor; the mechanisms are speculation, optimistic concurrency, deadlines
and verified commit.

| Metaphor | Mechanism | Where |
|---|---|---|
| superposition | N branches of one cell run on scoped threads | `qhr_sched::Scheduler::superpose` |
| amplitude | `Branch::weight`, orders and prunes only | `qhr_sched::Branch` |
| measurement | first branch passing `Cell::verify` is committed | `Fate::Won` |
| entanglement | `Versioned<T>::commit` fails if the snapshot is stale | `qhr_cell::Versioned` |
| decoherence | `Deadline`; late outputs are never read | `Fate::Expired` |
| gate | `Cell`: pure, deterministic, budgeted (default 1 ms) | `qhr_cell::Cell` |

## Rules

0. Cells hold no locks and do no I/O. They take a `Snapshot<T>` or plain
   input and return an owned output.
1. Cells are deterministic, so every committed branch can be replayed and
   re-hashed from the DUCTEI log.
2. QHR owns no durable state. `qhr_sched::commit` writes a
   `CollapseReceipt` as an ordinary `Envelope` (key `qhr/collapse/<cell>`,
   scope `qhr.receipt`, schema 1) through `ductei_core::Channel`, so the
   scope policy, causal gate and fsynced JSONL log apply unchanged.
3. Receipts form a SHA-256 hash chain (`prev` -> `hash`), domain separated
   and length prefixed. `qhr_sched::verify_chain` replays and checks it;
   a ward/QFLTL integrity pass should call it.
4. Cancellation is cooperative. A cell that loops polls `Ctx::cancelled`.
   A cell that ignores it delays collapse until it returns (scoped threads
   are always joined), so the `Deadline` is only as sharp as the cells.
5. Fan-out is capped (default `available_parallelism * 2`). With equal
   weights, pruning is positional: pass weights (J-lens or Jev scores) when
   order matters.

## Measured

Release, 2-core container, 8 trivial branches, 2000 collapses:
about 273 us per collapse, dominated by thread spawn. On xing-pc (16
threads) expect less, but per-collapse spawn is the floor; a persistent
worker pool is the next step if sub-100 us collapses are needed.

```powershell
cargo run --release -p qhr-sched --example overhead
```

## First consumers (planned)

0. brain act guard: candidate actions as branches, J-lens score as weight,
   the guard as `verify`.
1. Player Harness motor loop: high-Hz motor branches as cells, strategic
   brain as the measurement.

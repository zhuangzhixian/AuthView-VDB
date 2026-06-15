# Acknowledgements

## AuthView-VDB

**AuthView-VDB** is an independent research prototype. It starts from the
[V3DB](https://github.com/TabibitoQZP/zk-IVF-PQ) codebase (imported at tag
`v3db-import-baseline`) and is being extended toward **verifiable vector search
over committed authorization views**.

Authorization-view features described in this repository's research documents
are **planned extensions**. They are not implemented in the current baseline.

## V3DB

The baseline implementation implements audit-on-demand zero-knowledge proofs for
verifiable IVF-PQ vector search over committed snapshots, as described in:

> Zipeng Qiu, Wenjie Qu, Jiaheng Zhang, and Binhang Yuan.
> **V3DB: Audit-on-Demand Zero-Knowledge Proofs for Verifiable Vector Search
> over Committed Snapshots.**
> arXiv:2603.03065, 2026.

Upstream repository: https://github.com/TabibitoQZP/zk-IVF-PQ

Implementation details for the imported baseline are referenced in the original
technical note (`Technical_Details_of_V3DB.pdf`) linked from the V3DB README.

## License and attribution note

The imported V3DB baseline does not include a top-level `LICENSE` file in this
repository snapshot. Preserve any copyright, citation, or attribution information
present in upstream sources when extending this codebase. Confirm licensing with
the V3DB authors before redistribution beyond research use.

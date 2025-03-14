# VSEL Pre-print — Submission Package

## Paper

**Title:** VSEL: Verifiable Semantic Execution Layer — Closing the Gap Between Verified Execution and Correct Execution Through Formally Bound Semantic Proof Systems

**Author:** Mayckon Giovani (mayckongiovani.xyz)

**Date:** March 31, 2026

**Version:** v1.0 (Initial preprint release)

## Files

- `vsel-preprint.tex` — LaTeX source (self-contained, no external dependencies beyond standard packages)
- `vsel-preprint.pdf` — Compiled PDF (24 pages)

## arXiv Submission

### Primary Category
- **cs.CR** — Cryptography and Security

### Cross-list Categories
- **cs.PL** — Programming Languages
- **cs.LO** — Logic in Computer Science
- **cs.FL** — Formal Languages and Automata Theory

### MSC Classes
- 68Q60 (Specification and verification)
- 94A60 (Cryptography)
- 03B70 (Logic in computer science)
- 68Q45 (Formal languages and automata)

### ACM Classes
- D.2.4 (Software/Program Verification)
- F.3.1 (Specifying and Verifying and Reasoning about Programs)
- E.3 (Data Encryption)
- C.2.4 (Distributed Systems)

## Abstract

Contemporary cryptographic execution systems—particularly those employing zero-knowledge proofs—provide strong guarantees that a computation satisfies a given arithmetic circuit. However, satisfying a circuit is not equivalent to executing correctly with respect to the intended semantics of the system being proven. This paper identifies and formalizes the semantic gap: the class of failures in which execution is provably valid under a proof system yet provably invalid under the system's formal specification. We present the Verifiable Semantic Execution Layer (VSEL), a layered architecture that binds formal specification, execution, constraint derivation, proof generation, and verification into a single semantically coherent pipeline.

## Compilation

```bash
pdflatex vsel-preprint.tex
pdflatex vsel-preprint.tex  # second pass for cross-references
pdflatex vsel-preprint.tex  # third pass for stable TOC
```

Required packages: amsmath, amssymb, amsthm, mathtools, hyperref, geometry, enumitem, booktabs, tikz-cd, cleveref, xcolor, fancyhdr, datetime2

## License

This preprint is made available for academic and research purposes. All rights reserved by the author.

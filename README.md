# PRISM Artifacts

Each command prints the numbers of the paper listed beside it. The scripts need Python 3 and only the standard library.

| Numbers in the paper | Command |
| --- | --- |
| Table III, label distribution over the 8,119 pairs (RQ1) | `python3 scripts/paper_tables.py`, part 1 |
| Table IV, vulnerability types, and the Pearson correlation between the label distributions of the 353 pairs and of the corpus (RQ2) | `python3 scripts/paper_tables.py`, part 2 |
| Table V, taint analysis, and the counts that the text derives from it (RQ2) | `python3 scripts/rq2_table5.py` |
| The five CodeQL rows of Table V, recomputed from the CodeQL results and the labels | `python3 scripts/rq2_codeql_rows.py` |
| Table VI, per-label propagation rates (RQ2) | `python3 scripts/paper_tables.py`, part 3 |
| Tables VII and VIII, backward slicing (RQ3) | `python3 scripts/paper_tables.py`, part 4 |

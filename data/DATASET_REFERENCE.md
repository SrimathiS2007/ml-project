# Dataset reference
**HTTP DATASET CSIC 2010** - Torrano-Gimenez, Perez-Villegas, Alvarez Maranon (Spanish National Research Council, CSIC).
Web traffic to an e-commerce app: 36,000 normal training + 36,000 normal test + 25,065 anomalous requests
(SQL injection, XSS, file disclosure, parameter tampering ...).
Raw files: https://github.com/baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER (also on Kaggle).
`data/csic_parsed.csv` = the raw files converted to one line per request, duplicates removed (34,594 rows) by `parse_csic_raw.py`.
Synthetic data is generated inside `1_prepare_data.py`. Verify availability/licence before submission.

# Dataset

Recommended: **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository, ~235k labelled URLs,
published under CC BY 4.0 - confirm the license on the dataset page before citing it).

1. Download the CSV from the UCI page and save it as `dataset/phiusiil.csv`.
2. Needed columns: the raw URL column (`URL`) and the label column (`label`; in this dataset 1 = legitimate, 0 = phishing).
   Verify this on the dataset page. The training script (next stage) re-extracts features from the URL string,
   so training and serving use identical code.
3. Do not commit the CSV (see `.gitignore`).

Record in your report: source URL, access date, license, row counts, class balance.

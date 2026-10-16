# Dataset documentation

## 1. Included file: `sample_urls.csv` (demo only)

- 143 URLs (77 legitimate, 66 phishing-style), columns: `url`, `label` (0 = legitimate, 1 = phishing).
- **Hand-written by the project author for offline demonstration.** Legitimate entries are
  well-known public sites; "phishing" entries are *made-up* URLs that imitate common patterns
  (IP-address hosts, `@` symbols, many hyphens, look-alike names). They are not real phishing
  reports, and the domains should not be visited.
- Regenerate it with `python dataset/build_sample_dataset.py`.
- **It is NOT a validated phishing dataset.** Because it was written by hand to show the six
  features, a model trained on it will look very accurate, but that says nothing about how it
  would perform on real-world URLs.

## 2. Recommended real public dataset (not bundled)

**PhiUSIIL Phishing URL Dataset** - UCI Machine Learning Repository
- Page: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Authors: Arvind Prasad and Shalini Chandra (2024)
- License: Creative Commons Attribution 4.0 (CC BY 4.0), as stated on the UCI page.
  Please re-check the license and citation text on that page before using or redistributing it.
- It contains a URL column and a label column. Check the dataset's own documentation for
  what each label value means - in this dataset, `1` is believed to mean *legitimate*, the
  reverse of this project, so use the `--invert-labels` flag after confirming.

### Training on it

1. Download the CSV from the page above and put it in this folder (not included in the ZIP).
2. From the project folder run:

       python train_model.py --data dataset/PhiUSIIL_Phishing_URL_Dataset.csv --url-column URL --label-column label --invert-labels

   (Adjust the file and column names to match the file you downloaded.)
3. The script prints and saves the real accuracy and confusion matrix from a held-out test split.

Other public sources exist (for example PhishTank and OpenPhish feeds) but have their own terms of use.

## 3. Limitations

Only 6 simple URL-text features are used. Real phishing detectors use many more signals, and
dataset collection bias (for example, how legitimate URLs were sampled) can strongly affect results.

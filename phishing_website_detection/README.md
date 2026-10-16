# Phishing Website Detection Using Machine Learning

A beginner-level cybersecurity project. A Streamlit page lets you type a URL; a Random Forest
model (Scikit-learn) looks at six simple features of the URL text and predicts whether it looks
**legitimate** or **phishing**. The website is **never opened**, and no passwords or personal
information are collected.

> **Honest note:** The bundled model is trained on a tiny, hand-written *sample* dataset so the
> project works offline. Its accuracy (shown in the app after training) only describes that
> sample. It is **not** a validated phishing detector. For meaningful results, train on a real
> public dataset (see `dataset/README.md`).

## Project structure

    phishing_website_detection/
    ├── app.py                  Streamlit web page
    ├── train_model.py          Trains, evaluates and saves the model
    ├── feature_extraction.py   URL feature extraction (shared by training and the app)
    ├── requirements.txt        Python libraries
    ├── README.md               This file
    ├── .gitignore
    ├── dataset/                sample_urls.csv, dataset README, script that builds the sample
    ├── model/                  phishing_model.joblib and model_config.json (metrics)
    └── tests/                  unit tests

## The six URL features

| Feature | Meaning |
|---|---|
| url_length | Number of characters in the URL |
| num_dots | Number of `.` characters |
| num_hyphens | Number of `-` characters |
| has_ip_address | 1 if the hostname is an IP address (e.g. `http://192.168.1.5/`) |
| has_at_symbol | 1 if the URL contains `@` |
| uses_https | 1 if the URL starts with `https://` |

These are **indicators, not proof**. Many safe sites have long URLs, and phishing sites can use
HTTPS and short URLs. Treat the prediction as a rough hint only.

## How it works (for your presentation)

1. `feature_extraction.py` turns a URL into six numbers. The same function is used in training and in the app.
2. `train_model.py` loads the CSV, extracts features, splits the data into train and test sets,
   trains a Random Forest, measures accuracy / precision / recall / confusion matrix on the
   test set, and saves everything into `model/`.
3. `app.py` loads the saved model, extracts features from the entered URL, and shows the prediction
   plus the saved evaluation results. All numbers come from the training run - none are typed in by hand.

## Setup on Windows

1. **Extract** `phishing_website_detection.zip` (right-click -> Extract All...).
2. **Open the folder in VS Code**: File -> Open Folder -> choose `phishing_website_detection`.
3. **Open a terminal** in VS Code (Terminal -> New Terminal) and **create a virtual environment**:

       python -m venv venv
       venv\Scripts\activate

   (If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first.)
4. **Install dependencies**:

       pip install -r requirements.txt

5. **Train the model** (a trained model is already included; re-run this if you change the data
   or if `model/` is missing or gives a scikit-learn version error):

       python train_model.py

6. **Start the app**:

       streamlit run app.py

7. **Open the local URL** printed in the terminal (usually http://localhost:8501).

## Run the tests

    python -m unittest discover -s tests

## Using a real dataset

See `dataset/README.md` for the PhiUSIIL dataset source, license, and the exact command.

## Limitations

- Only six simple features; real detectors use far more (domain age, page content, etc.).
- The sample dataset is tiny and hand-written, so reported accuracy is not meaningful for real-world use.
- Not for real security decisions. Predictions may be wrong in both directions.

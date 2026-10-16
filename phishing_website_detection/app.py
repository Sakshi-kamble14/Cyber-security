"""
app.py - Streamlit interface for the Phishing Website Detection System.
Run with:  streamlit run app.py

The app only analyses the TEXT of the URL. It never opens the website and never
asks for passwords or personal information.
"""

import json
import os

import joblib
import pandas as pd
import streamlit as st

from feature_extraction import describe_indicators, predict_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.joblib")
CONFIG_PATH = os.path.join(BASE_DIR, "model", "model_config.json")


@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


st.set_page_config(page_title="Phishing Website Detection System", page_icon="🛡️")

st.title("Phishing Website Detection System")
st.write(
    "Type a website address and this beginner project will look at a few simple "
    "features of the URL text and estimate whether it looks **legitimate** or "
    "**phishing**, using a Random Forest model from Scikit-learn."
)
st.warning(
    "Predictions may be incorrect. This is a learning project, not a security tool. "
    "Never rely on it to decide whether a site is safe."
)

if not (os.path.exists(MODEL_PATH) and os.path.exists(CONFIG_PATH)):
    st.error("No trained model found. Run `python train_model.py` first, then restart the app.")
    st.stop()

model = load_model()
config = load_config()

url = st.text_input("Website URL", placeholder="https://www.example.com/login")

if st.button("Check Website"):
    if not url.strip():
        st.info("Please enter a URL first.")
    else:
        label, phishing_prob, features = predict_url(model, url)
        if label == 1:
            st.error(f"⚠️ This URL looks like it could be PHISHING (model score: {phishing_prob:.0%}).")
        else:
            st.success(f"✅ This URL looks LEGITIMATE to the model (phishing score: {phishing_prob:.0%}).")
        st.caption("The website was NOT visited. Only the text of the URL was analysed.")

        st.subheader("Features extracted from the URL")
        st.table(pd.DataFrame({"Feature": list(features.keys()), "Value": list(features.values())}))
        st.subheader("What this means")
        for note in describe_indicators(features):
            st.write(f"- {note}")
        st.info(
            "These features are only indicators. A long URL or a hyphen does not prove a site is "
            "malicious, and a clean-looking URL does not prove it is safe."
        )

st.divider()
st.header("Model evaluation")
m = config["metrics"]
st.write(
    f"Model: {config['model_type']} | Dataset file: `{config['dataset_file']}` | "
    f"Trained: {config['trained_at']} | Train/Test sizes: {m['train_size']}/{m['test_size']}"
)
c1, c2, c3 = st.columns(3)
c1.metric("Accuracy (test set)", f"{m['accuracy']:.1%}")
c2.metric("Precision (phishing)", f"{m['precision_phishing']:.1%}")
c3.metric("Recall (phishing)", f"{m['recall_phishing']:.1%}")

st.subheader("Confusion matrix")
cm = pd.DataFrame(
    m["confusion_matrix"],
    index=["Actual: legitimate", "Actual: phishing"],
    columns=["Predicted: legitimate", "Predicted: phishing"],
)
st.table(cm)

if config.get("used_sample_dataset"):
    st.warning(
        "The model was trained on the tiny, hand-written SAMPLE dataset included for offline demos. "
        "These numbers only describe that small sample and do NOT show that the model can detect "
        "real phishing sites. See dataset/README.md to train on a real public dataset."
    )

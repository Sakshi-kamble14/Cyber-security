# Phishing Website Detection System Using Machine Learning

Status: Stages 1-2 complete (structure, MySQL schema, URL feature extraction + tests).
Remaining: training/evaluation, Flask API, React UI, integration, docs.

## Windows quick start (so far)
```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m pytest
mysql -u root -p < database\schema.sql
copy .env.example .env
```
Safety: submitted URLs are only parsed as text. They are never opened, resolved, or executed.

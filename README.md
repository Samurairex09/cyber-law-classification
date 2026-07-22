# Cyber Law Classification System

A cyber incident classification tool that takes network traffic features, predicts the type of attack using a trained Random Forest model, and maps the prediction to the relevant section of India's IT Act (2000) — including the applicable penalty. Incidents are logged to a local database and can be exported as PDF reports.

## How it works

1. Network traffic features (protocol, service, state, byte/packet counts, timing stats, etc.) are submitted to the API.
2. A Random Forest classifier (trained on the UNSW-NB15 dataset) predicts the attack category — e.g. Fuzzers, DoS, Backdoor, Exploits, Reconnaissance, Shellcode, Worms, or "no offence."
3. The prediction is mapped to the corresponding IT Act section and penalty.
4. The incident is stored in SQLite (`incidents.db`), viewable, editable, and deletable via the API.
5. A formatted PDF incident report can be generated on demand.

## Stack

- **Backend:** FastAPI, scikit-learn (via `joblib`), NumPy
- **Frontend:** Streamlit
- **Storage:** SQLite
- **Reporting:** ReportLab (PDF generation)
- **Dataset:** UNSW-NB15 (network intrusion detection benchmark)

## Project structure

```
main.py          FastAPI backend — prediction, incident CRUD, PDF report generation
app.py           Streamlit frontend
rf_model.pkl     Trained Random Forest classifier
label_encoder.pkl, ord_encoder.pkl   Encoders for model input/output
incidents.db     SQLite database of logged incidents
UNSW_NB15_testing-set.csv, test_sample.csv   Reference/test data
```

## Running locally

```bash
pip install -r requirements.txt

# Terminal 1 — API
uvicorn main:app --reload

# Terminal 2 — UI
streamlit run app.py
```

The API runs on `http://127.0.0.1:8000`, and the Streamlit UI talks to it directly.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/predict` | Classify network traffic and log the incident |
| GET | `/incidents` | List all logged incidents |
| PUT | `/incident/{id}` | Update analyst notes on an incident |
| DELETE | `/incident/{id}` | Delete an incident |
| POST | `/generate-report/{id}` | Generate a PDF report for an incident |

## Note

This is a student/academic project. The IT Act section mappings and penalties are for illustrative and educational purposes, not a substitute for legal advice.

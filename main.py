from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import joblib
import numpy as np
import sqlite3
import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ── App Initialization 
app = FastAPI(title="Cyber Incident Classification API")

# ── Load Models 
rf_model = joblib.load("rf_model.pkl")
encoder  = joblib.load("label_encoder.pkl")
ord_enc  = joblib.load("ord_encoder.pkl")
print("Models loaded successfully")

# ── Compliance Maps
label_to_attack = {
    "Sec 66 – Fuzzers":        "Fuzzers",
    "Sec 66 – Analysis":       "Analysis",
    "Sec 66 – Backdoor":       "Backdoor",
    "Sec 43(f) – DoS":         "DoS",
    "Sec 66 – Exploits":       "Exploits",
    "Sec 66 – Generic":        "Generic",
    "Sec 66B – Reconnaissance": "Reconnaissance",
    "Sec 66F – Shellcode":     "Shellcode",
    "Sec 66 – Worms":          "Worms",
    "No offence":              "Normal Traffic"
}

compliance_map = {
    "Sec 66 – Fuzzers": {
        "section": "Section 66",
        "description": "Fuzzing Attack — sending malformed data to find vulnerabilities",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "Sec 66 – Analysis": {
        "section": "Section 66",
        "description": "Analysis Attack — port scanning and information gathering",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "Sec 66 – Backdoor": {
        "section": "Section 66",
        "description": "Backdoor Attack — unauthorised hidden access to a system",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "Sec 43(f) – DoS": {
        "section": "Section 43(f)",
        "description": "Denial of Service Attack — disrupting access to a system",
        "penalty": "Compensation up to ₹1 crore"
    },
    "Sec 66 – Exploits": {
        "section": "Section 66",
        "description": "Exploit Attack — taking advantage of a known software vulnerability",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "Sec 66 – Generic": {
        "section": "Section 66",
        "description": "Generic Attack — cryptographic attack targeting block ciphers",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "Sec 66B – Reconnaissance": {
        "section": "Section 66B",
        "description": "Reconnaissance — network probing and intelligence gathering",
        "penalty": "3 years imprisonment and/or fine up to ₹1 lakh"
    },
    "Sec 66F – Shellcode": {
        "section": "Section 66F",
        "description": "Cyber Terrorism — shellcode injection targeting critical systems",
        "penalty": "Life imprisonment"
    },
    "Sec 66 – Worms": {
        "section": "Section 66",
        "description": "Worm Attack — self-replicating malware spreading across networks",
        "penalty": "3 years imprisonment and/or fine up to ₹5 lakhs"
    },
    "No offence": {
        "section": "N/A",
        "description": "No malicious activity detected",
        "penalty": "N/A"
    }
}

# ── Database 
def init_db():
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            confidence REAL,
            it_act_section TEXT,
            description TEXT,
            penalty TEXT,
            network_features TEXT,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ── Pydantic Models 
class NetworkInput(BaseModel):
    dur: float
    proto: str
    service: str
    state: str
    spkts: float
    dpkts: float
    sbytes: float
    dbytes: float
    rate: float
    sload: float
    dload: float
    sloss: float
    dloss: float
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float
    swin: float
    dwin: float
    stcpb: float
    dtcpb: float
    tcprtt: float
    synack: float
    ackdat: float
    smean: float
    dmean: float
    trans_depth: float
    response_body_len: float
    ct_src_dport_ltm: float
    ct_dst_sport_ltm: float
    is_ftp_login: float
    ct_ftp_cmd: float
    ct_flw_http_mthd: float
    is_sm_ips_ports: float

class NotesUpdate(BaseModel):
    notes: str

# ── Endpoints 
@app.post("/predict")
def predict(input_data: NetworkInput):
    # Encode categorical fields
    cat_values  = ord_enc.transform([[input_data.proto, input_data.service, input_data.state]])
    proto_enc   = cat_values[0][0]
    service_enc = cat_values[0][1]
    state_enc   = cat_values[0][2]

    features = np.array([[
        input_data.dur, proto_enc, service_enc, state_enc,
        input_data.spkts, input_data.dpkts, input_data.sbytes, input_data.dbytes,
        input_data.rate, input_data.sload, input_data.dload,
        input_data.sloss, input_data.dloss,
        input_data.sinpkt, input_data.dinpkt,
        input_data.sjit, input_data.djit,
        input_data.swin, input_data.dwin,
        input_data.stcpb, input_data.dtcpb,
        input_data.tcprtt, input_data.synack, input_data.ackdat,
        input_data.smean, input_data.dmean,
        input_data.trans_depth, input_data.response_body_len,
        input_data.ct_src_dport_ltm, input_data.ct_dst_sport_ltm,
        input_data.is_ftp_login, input_data.ct_ftp_cmd,
        input_data.ct_flw_http_mthd, input_data.is_sm_ips_ports
    ]])

    prediction     = rf_model.predict(features)[0]
    confidence     = rf_model.predict_proba(features)[0].max()
    label          = encoder.inverse_transform([prediction])[0]
    attack_category = label_to_attack.get(label, "Unknown")
    compliance     = compliance_map.get(label, {})
    it_act_section = compliance.get("section", "N/A")

    network_features = json.dumps({
        "proto": input_data.proto, "service": input_data.service,
        "state": input_data.state, "dur": input_data.dur,
        "sbytes": input_data.sbytes, "dbytes": input_data.dbytes,
        "spkts": input_data.spkts, "dpkts": input_data.dpkts,
        "rate": input_data.rate, "sload": input_data.sload,
        "dload": input_data.dload, "tcprtt": input_data.tcprtt,
        "synack": input_data.synack, "ackdat": input_data.ackdat
    })

    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incident_reports
        (timestamp, attack_type, confidence, it_act_section, description, penalty, network_features, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        attack_category,
        round(float(confidence), 4),
        it_act_section,
        compliance.get("description", ""),
        compliance.get("penalty", ""),
        network_features,
        ""
    ))
    conn.commit()
    conn.close()

    return {
        "attack_classification": attack_category,
        "it_act_section": it_act_section,
        "description": compliance.get("description", ""),
        "penalty": compliance.get("penalty", ""),
        "confidence": round(float(confidence), 4)
    }


@app.get("/incidents")
def get_incidents():
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incident_reports")
    rows = cursor.fetchall()
    conn.close()

    incidents = []
    for row in rows:
        incidents.append({
            "id": row[0],
            "timestamp": row[1],
            "attack_type": row[2],
            "confidence": row[3],
            "it_act_section": row[4],
            "description": row[5],
            "penalty": row[6],
            "network_features": row[7],
            "notes": row[8]
        })
    return {"incidents": incidents}


@app.put("/incident/{id}")
def update_notes(id: int, update: NotesUpdate):
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE incident_reports SET notes = ? WHERE id = ?",
        (update.notes, id)
    )
    conn.commit()
    conn.close()
    return {"message": f"Incident {id} updated successfully"}


@app.delete("/incident/{id}")
def delete_incident(id: int):
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incident_reports WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return {"message": f"Incident {id} deleted successfully"}


@app.post("/generate-report/{id}")
def generate_report(id: int):
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incident_reports WHERE id = ?", (id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"error": f"Incident {id} not found"}

    incident_id    = row[0]
    timestamp      = row[1]
    attack_type    = row[2]
    confidence     = row[3]
    it_act_section = row[4]
    description    = row[5]
    penalty        = row[6]
    net_features   = json.loads(row[7]) if row[7] else {}
    notes          = row[8]

    filename = f"incident_report_{incident_id}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "Cyber Incident Report")
    c.line(50, height - 60, width - 50, height - 60)

    # Incident Summary
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, height - 85, "Incident Summary")
    c.line(50, height - 90, width - 50, height - 90)

    summary_fields = [
        ("Incident ID:",          str(incident_id)),
        ("Timestamp:",            timestamp),
        ("Attack Classification:", attack_type),
        ("Confidence Score:",     str(confidence)),
        ("IT Act Section:",       it_act_section),
        ("Description:",          description),
        ("Penalty:",              penalty),
        ("Analyst Notes:",        notes if notes else "None"),
    ]

    y = height - 110
    for label, value in summary_fields:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, label)
        c.setFont("Helvetica", 11)
        c.drawString(220, y, value)
        y -= 22

    # Network Traffic Details
    y -= 10
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Network Traffic Details")
    y -= 8
    c.line(50, y, width - 50, y)
    y -= 18

    net_fields = [
        ("Protocol:",       str(net_features.get("proto", "N/A"))),
        ("Service:",        str(net_features.get("service", "N/A"))),
        ("State:",          str(net_features.get("state", "N/A"))),
        ("Duration:",       str(net_features.get("dur", "N/A"))),
        ("Source Bytes:",   str(net_features.get("sbytes", "N/A"))),
        ("Dest Bytes:",     str(net_features.get("dbytes", "N/A"))),
        ("Source Packets:", str(net_features.get("spkts", "N/A"))),
        ("Dest Packets:",   str(net_features.get("dpkts", "N/A"))),
        ("Rate:",           str(net_features.get("rate", "N/A"))),
        ("Source Load:",    str(net_features.get("sload", "N/A"))),
        ("Dest Load:",      str(net_features.get("dload", "N/A"))),
        ("TCP RTT:",        str(net_features.get("tcprtt", "N/A"))),
        ("Syn-Ack Time:",   str(net_features.get("synack", "N/A"))),
        ("Ack Data Time:",  str(net_features.get("ackdat", "N/A"))),
    ]

    for label, value in net_fields:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, label)
        c.setFont("Helvetica", 11)
        c.drawString(220, y, value)
        y -= 20

    # Footer
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 30, "This report is auto-generated. Legal references are for compliance guidance only.")
    c.save()

    return FileResponse(filename, media_type="application/pdf", filename=filename)
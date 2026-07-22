import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="Cyber Incident Classification System",
    page_icon="🛡️",
    layout="wide"
)

page = st.sidebar.selectbox(
    "Navigation",
    ["🔍 Predict", "📋 Incidents", "📄 Generate Report"]
)

# ── PAGE 1: PREDICT 
if page == "🔍 Predict":
    st.title("🔍 Cyber Incident Classifier")
    st.divider()

    tab1, tab2 = st.tabs(["📝 Manual Input", "📂 CSV Upload"])

    # ── TAB 1: MANUAL INPUT 
    with tab1:
        st.markdown("Enter network traffic features below to classify the incident.")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Protocol Info")
            proto   = st.text_input("Protocol (proto)", value="tcp")
            service = st.text_input("Service", value="-")
            state   = st.text_input("State", value="FIN")
            dur     = st.number_input("Duration (dur)", value=0.0, step=0.0001, format="%.4f")

        with col2:
            st.subheader("Traffic Volume")
            sbytes = st.number_input("Source Bytes (sbytes)", value=0.0, step=0.0001, format="%.4f")
            dbytes = st.number_input("Dest Bytes (dbytes)", value=0.0, step=0.0001, format="%.4f")
            spkts  = st.number_input("Source Packets (spkts)", value=0.0, step=0.0001, format="%.4f")
            dpkts  = st.number_input("Dest Packets (dpkts)", value=0.0, step=0.0001, format="%.4f")
            sload  = st.number_input("Source Load (sload)", value=0.0, step=0.0001, format="%.4f")
            dload  = st.number_input("Dest Load (dload)", value=0.0, step=0.0001, format="%.4f")
            rate   = st.number_input("Rate", value=0.0, step=0.0001, format="%.4f")

        with col3:
            st.subheader("Connection Stats")
            sloss  = st.number_input("sloss", value=0.0, step=0.0001, format="%.4f")
            dloss  = st.number_input("dloss", value=0.0, step=0.0001, format="%.4f")
            sinpkt = st.number_input("sinpkt", value=0.0, step=0.0001, format="%.4f")
            dinpkt = st.number_input("dinpkt", value=0.0, step=0.0001, format="%.4f")
            sjit   = st.number_input("sjit", value=0.0, step=0.0001, format="%.4f")
            djit   = st.number_input("djit", value=0.0, step=0.0001, format="%.4f")
            swin   = st.number_input("swin", value=0.0, step=0.0001, format="%.4f")
            dwin   = st.number_input("dwin", value=0.0, step=0.0001, format="%.4f")

        st.divider()
        col4, col5 = st.columns(2)

        with col4:
            st.subheader("TCP Info")
            stcpb  = st.number_input("stcpb", value=0.0, step=0.0001, format="%.4f")
            dtcpb  = st.number_input("dtcpb", value=0.0, step=0.0001, format="%.4f")
            tcprtt = st.number_input("tcprtt", value=0.0, step=0.0001, format="%.4f")
            synack = st.number_input("synack", value=0.0, step=0.0001, format="%.4f")
            ackdat = st.number_input("ackdat", value=0.0, step=0.0001, format="%.4f")
            smean  = st.number_input("smean", value=0.0, step=0.0001, format="%.4f")
            dmean  = st.number_input("dmean", value=0.0, step=0.0001, format="%.4f")

        with col5:
            st.subheader("Application Layer")
            trans_depth       = st.number_input("trans_depth", value=0.0, step=0.0001, format="%.4f")
            response_body_len = st.number_input("response_body_len", value=0.0, step=0.0001, format="%.4f")
            ct_src_dport_ltm  = st.number_input("ct_src_dport_ltm", value=0.0, step=0.0001, format="%.4f")
            ct_dst_sport_ltm  = st.number_input("ct_dst_sport_ltm", value=0.0, step=0.0001, format="%.4f")
            is_ftp_login      = st.number_input("is_ftp_login", value=0.0, step=0.0001, format="%.4f")
            ct_ftp_cmd        = st.number_input("ct_ftp_cmd", value=0.0, step=0.0001, format="%.4f")
            ct_flw_http_mthd  = st.number_input("ct_flw_http_mthd", value=0.0, step=0.0001, format="%.4f")
            is_sm_ips_ports   = st.number_input("is_sm_ips_ports", value=0.0, step=0.0001, format="%.4f")

        st.divider()

        if st.button("🔍 Classify Incident", use_container_width=True):
            payload = {
                "dur": dur, "proto": proto, "service": service, "state": state,
                "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes,
                "rate": rate, "sload": sload, "dload": dload, "sloss": sloss,
                "dloss": dloss, "sinpkt": sinpkt, "dinpkt": dinpkt, "sjit": sjit,
                "djit": djit, "swin": swin, "dwin": dwin, "stcpb": stcpb,
                "dtcpb": dtcpb, "tcprtt": tcprtt, "synack": synack, "ackdat": ackdat,
                "smean": smean, "dmean": dmean, "trans_depth": trans_depth,
                "response_body_len": response_body_len, "ct_src_dport_ltm": ct_src_dport_ltm,
                "ct_dst_sport_ltm": ct_dst_sport_ltm, "is_ftp_login": is_ftp_login,
                "ct_ftp_cmd": ct_ftp_cmd, "ct_flw_http_mthd": ct_flw_http_mthd,
                "is_sm_ips_ports": is_sm_ips_ports
            }

            with st.spinner("Classifying..."):
                response = requests.post(f"{API_URL}/predict", json=payload)

            if response.status_code == 200:
                result = response.json()
                st.success("Classification Complete")
                r1, r2 = st.columns(2)
                with r1:
                    st.metric("Attack Classification", result["attack_classification"])
                    st.metric("IT Act Section", result["it_act_section"])
                with r2:
                    st.metric("Confidence Score", f"{result['confidence'] * 100:.1f}%")
                    st.metric("Penalty", result["penalty"])
                st.info(f"📝 Description: {result['description']}")
            else:
                st.error("Prediction failed. Is the FastAPI server running?")

    # ── TAB 2: CSV UPLOAD 
    with tab2:
        st.markdown("Upload a CSV file with network traffic data. Each row will be classified separately.")
        st.caption("Expected columns match the UNSW-NB15 feature set. Use the exported test_sample.csv as reference.")

        uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

        if uploaded_file is not None:
            import pandas as pd
            df = pd.read_csv(uploaded_file)
            st.success(f"Loaded {len(df)} rows.")
            st.dataframe(df.head(), use_container_width=True)

            if st.button("🔍 Classify All Rows", use_container_width=True):
                results = []
                progress = st.progress(0)

                for i, row in df.iterrows():
                    payload = {
                        "dur": row.get("dur", 0), "proto": str(row.get("proto", "tcp")),
                        "service": str(row.get("service", "-")), "state": str(row.get("state", "FIN")),
                        "spkts": row.get("spkts", 0), "dpkts": row.get("dpkts", 0),
                        "sbytes": row.get("sbytes", 0), "dbytes": row.get("dbytes", 0),
                        "rate": row.get("rate", 0), "sload": row.get("sload", 0),
                        "dload": row.get("dload", 0), "sloss": row.get("sloss", 0),
                        "dloss": row.get("dloss", 0), "sinpkt": row.get("sinpkt", 0),
                        "dinpkt": row.get("dinpkt", 0), "sjit": row.get("sjit", 0),
                        "djit": row.get("djit", 0), "swin": row.get("swin", 0),
                        "dwin": row.get("dwin", 0), "stcpb": row.get("stcpb", 0),
                        "dtcpb": row.get("dtcpb", 0), "tcprtt": row.get("tcprtt", 0),
                        "synack": row.get("synack", 0), "ackdat": row.get("ackdat", 0),
                        "smean": row.get("smean", 0), "dmean": row.get("dmean", 0),
                        "trans_depth": row.get("trans_depth", 0),
                        "response_body_len": row.get("response_body_len", 0),
                        "ct_src_dport_ltm": row.get("ct_src_dport_ltm", 0),
                        "ct_dst_sport_ltm": row.get("ct_dst_sport_ltm", 0),
                        "is_ftp_login": row.get("is_ftp_login", 0),
                        "ct_ftp_cmd": row.get("ct_ftp_cmd", 0),
                        "ct_flw_http_mthd": row.get("ct_flw_http_mthd", 0),
                        "is_sm_ips_ports": row.get("is_sm_ips_ports", 0)
                    }

                    r = requests.post(f"{API_URL}/predict", json=payload)
                    if r.status_code == 200:
                        res = r.json()
                        results.append({
                            "Row": i + 1,
                            "Attack Classification": res["attack_classification"],
                            "IT Act Section": res["it_act_section"],
                            "Confidence": f"{res['confidence'] * 100:.1f}%",
                            "Penalty": res["penalty"]
                        })
                    progress.progress((i + 1) / len(df))

                st.success(f"Classified {len(results)} rows.")
                results_df = pd.DataFrame(results)
                st.dataframe(results_df, use_container_width=True)

                csv_out = results_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download Results as CSV",
                    data=csv_out,
                    file_name="batch_classification_results.csv",
                    mime="text/csv",
                    use_container_width=True
                )

# ── PAGE 2: INCIDENTS 
elif page == "📋 Incidents":
    st.title("📋 Incident Log")
    st.markdown("All logged incidents from the database.")
    st.divider()

    if st.button("🔄 Refresh", use_container_width=False):
        st.rerun()

    response = requests.get(f"{API_URL}/incidents")

    if response.status_code == 200:
        incidents = response.json()["incidents"]

        if not incidents:
            st.warning("No incidents logged yet. Run a prediction first.")
        else:
            st.success(f"{len(incidents)} incident(s) found.")
            st.dataframe(
                incidents,
                use_container_width=True,
                hide_index=True
            )

            st.divider()
            st.subheader("Update Analyst Notes")
            inc_id = st.number_input("Incident ID", min_value=1, step=1)
            notes  = st.text_area("Notes")

            if st.button("💾 Save Notes"):
                r = requests.put(
                    f"{API_URL}/incident/{int(inc_id)}",
                    json={"notes": notes}
                )
                if r.status_code == 200:
                    st.success(f"Notes saved for Incident {int(inc_id)}")
                else:
                    st.error("Failed to update notes.")

            st.divider()
            st.subheader("Delete Incident")
            del_id = st.number_input("Incident ID to Delete", min_value=1, step=1)
            if st.button("🗑️ Delete", type="primary"):
                r = requests.delete(f"{API_URL}/incident/{int(del_id)}")
                if r.status_code == 200:
                    st.success(f"Incident {int(del_id)} deleted.")
                    st.rerun()
                else:
                    st.error("Failed to delete incident.")
    else:
        st.error("Could not reach the API. Is FastAPI running?")

# ── PAGE 3: GENERATE REPORT 
elif page == "📄 Generate Report":
    st.title("📄 Incident Report Generator")
    st.markdown("Generate a downloadable PDF report for any logged incident.")
    st.divider()

    report_id = st.number_input("Enter Incident ID", min_value=1, step=1)

    if st.button("📄 Generate PDF Report", use_container_width=True):
        with st.spinner("Generating report..."):
            r = requests.post(f"{API_URL}/generate-report/{int(report_id)}")

        if r.status_code == 200:
            st.success("Report generated!")
            st.download_button(
                label="⬇️ Download PDF",
                data=r.content,
                file_name=f"incident_report_{int(report_id)}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        else:
            st.error(f"Could not generate report. Check if Incident {int(report_id)} exists.")
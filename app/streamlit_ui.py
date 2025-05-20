import sys
import os

# Ensure the root project directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


import pandas as pd
import streamlit as st
import os
import datetime
from feature_extraction.extract_dns_features import dns_extraction
from feature_extraction.extract_doh_features import doh_extraction
from app.dns_predict import predict_with_dns_model
from app.doh_predict import predict_with_doh_deepfm_model
from app.llm_agent import extract_detections, build_prompt, run_ollama


st.set_page_config(page_title="Data Exfiltration Detection Agent", layout="centered")
st.title("🔎 Data Exfiltration Detection Agent")

# File upload
uploaded_file = st.file_uploader("Choose a PCAP file to analyze", type=["pcap", "pcapng"])

if uploaded_file:
    if st.button("Analyze Traffic"):
        with st.spinner("Processing file and analyzing traffic..."):
            # Save uploaded file
            # Ensure 'uploads' folder exists
            os.makedirs("uploads", exist_ok=True)
            pcap_path = os.path.join("uploads", uploaded_file.name)
            with open(pcap_path, "wb") as f:
                f.write(uploaded_file.read())

            # Step 1: Feature extraction
            dns_df = dns_extraction(pcap_path)
            doh_df = doh_extraction(pcap_path)

            dns_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dns_tunnel_classifier.pt'))
            doh_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'doh_deepfm_model'))

            # Step 2: Predictions
            dns_pred_df = predict_with_dns_model(dns_df, model_path=dns_model_path)
            doh_pred_df = predict_with_doh_deepfm_model(doh_df, model_path=doh_model_path)

            # Step 3: Detection extraction
            dns_detections = extract_detections(dns_pred_df, "DNS Tunneling") if dns_pred_df is not None else []
            doh_detections = extract_detections(doh_pred_df, "DoH Tunneling") if doh_pred_df is not None else []
            all_detections = dns_detections + doh_detections

            # Step 4: Display detections
            st.subheader("Detected Events")
            if all_detections:
                display_df = pd.DataFrame(all_detections)
                st.dataframe(display_df, use_container_width=True)

                # Step 5: Run LLM agent
                st.subheader("Analysis Report")
                prompt = build_prompt(all_detections)
                print(f"Prompt sent:\n{prompt}")
                report = run_ollama(prompt)

                # Display report in styled container
                with st.container():
                    st.markdown(f"""
                    <div style='padding: 1em; background-color: #f6f8fa; border: 1px solid #d1d5da; border-radius: 6px;'>
                        <h4>🔍 <u>Analysis Summary:</u></h4>
                        <p style='margin-bottom: 0.5em;'>{report}</p>
                    </div>
                    """, unsafe_allow_html=True)

                # Save report
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                os.makedirs("static", exist_ok=True)
                report_path = f"static/report_{timestamp}.txt"
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(report)

                # Download button
                st.download_button(
                    label="⬇️ Download Report (TXT)",
                    data=report,
                    file_name="analysis_report.txt",
                    mime="text/plain"
                )
            else:
                st.info("✅ No tunneling activity detected in this file.")

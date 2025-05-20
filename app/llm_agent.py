import subprocess
import json

def extract_detections(df, attack_type):
    """
    Extract rows with predicted_label == 1 and format them for LLM
    """
    print(df.head(20))
    suspicious_rows = df[df["predicted_label"] == 1]
    detections = []
    for _, row in suspicious_rows.iterrows():
        detection = {
            "type": attack_type,
            "score": float(row["prediction_score"]),
        }

        # Include domain only for DNS Tunneling
        if attack_type == "DNS Tunneling":
            detection["domain"] = row.get("domain", "N/A"),
            detection["src_ip"] = row.get("SourceIP", "N/A"),

        # Include destination IP if available
        if "DestinationIP" in row:
            detection["dst_ip"] = row["DestinationIP"]

        detections.append(detection)
    return detections


def build_prompt(detections):
    """
    Build a structured prompt for the LLM agent given list of detections
    """
    prompt = f"""
You are a cybersecurity analyst. Based on the following detection results, write a detailed and professional report in markdown format.

The report should include:
- An executive summary of what was detected.
- A timeline or pattern observed (if any).
- The type of tunneling attack and how it was detected.
- Risk level of the findings.
- Recommended mitigation or follow-up actions.
Do not generate more than 100 words in the report. make it clear.

Detections:
{json.dumps(detections, indent=2)}
"""
    return prompt.strip()


def run_ollama(prompt, model_name="mistral"):
    """
    Run the given prompt with Ollama LLM and return the response
    """
    process = subprocess.Popen(
        ["ollama", "run", model_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding= "utf-8"
    )
    output, _ = process.communicate(prompt)
    return output.strip()

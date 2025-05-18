# DNS Tunneling Detection with LLM-Augmented Classifier

## Overview

This project is designed to analyze DNS traffic and detect anomalies, particularly DNS tunneling, by combining traditional feature extraction with deep learning technics and large language model (LLM) assistance. The goal is to create an end-to-end system that can extract relevant features from `.pcap` files, send them to the deep learning models to predict if they contain malicious behavior or not, and return the answer to the user with additional explanation from the LLM agent. 

## Goals

* Build a local system that enables easy `.pcap` upload and feature extraction.
* Create a structured dataset of DNS traffic for supervised Deep ML.
* Develop a pipeline for training a DNS tunneling classifier.
* Use an LLM to summarize or assess extracted traffic features.

## Components

* **Feature Extraction Backend**: Extracts statistical features from DNS queries and responses in `.pcap` files.
* **Flask API**: Accepts local `.pcap` file uploads and processes them.
* **LLM Integration (Ollama)**: Accepts extracted features and returns natural language analysis.
* **Deep Learning Models**: Two deep learning classifiers were trained separately:

  * One for **traditional DNS traffic**.
  * One for **DNS-over-HTTPS (DoH)** traffic.

## Dataset Creation Process

1. **Collection of Raw PCAP Files**:

   * To train our models, we used these datasets that we found:
     * https://github.com/ggyggy666/DNS-Tunnel-Datasets - For DNS data
     * https://www.unb.ca/cic/datasets/dohbrw-2020.html - For DOH data
   * In addition,
     * Benign data can be captured from real browsing activity or public corpora.
     * Malicious data can include known DNS tunneling tools (e.g., Iodine, dnscat2, etc.).

2. **Labeling**:

   * The datasets came pre-labeled `.pcap` with `0` (benign) or `1` (tunneled).

3. **Feature Extraction**:

   * Extract the following from each DNS query and its response (if found):

     * Domain length
     * Subdomain count
     * Shannon entropy
     * Number of digits and special characters
     * Query type
     * Response size
     * Average TTL
     * Source and destination IP string length
     * Message rate (per second/minute)
   * Save all features along with the label into a structured CSV file.
  
   * Extract the following from each DoH query and its response (if found):
     * TLS flow duration
     * Number of packets sent and received
     * Total bytes sent and received
     * Packet size statistics (mean, median, mode, variance, std)
     * Inter-arrival time statistics
     * Estimated response time between client and server packets
     * Coefficient of variation and skewness metrics
     * Timestamp of first packet in the flow
   * Save all features along with the label into a structured CSV file.

## Feature Extraction Process

We parse the `.pcap` using `scapy` and iterate through all DNS layers:

* Track query/response pairs using transaction ID + src/dst IP.
* Calculate string-based features (e.g., entropy, domain length).
* Use pandas to compute message rates over time.
* Support TLS/DNS-over-HTTPS analysis via port filtering (e.g., 443).

Output is stored as a CSV row per DNS query with corresponding features and (optionally) the label.

## LLM Integration via Ollama

After feature extraction:

* A summary (e.g., from `df.describe()`) is passed to a local LLM running via Ollama.
* The LLM is prompted to identify suspicious patterns and justify why they may or may not indicate DNS tunneling.
* This adds interpretability and supports manual threat analysis.

## API Usage

### Endpoint: `/upload`

* **Method**: POST
* **Payload**: `.pcap` file (form-data)
* **Response**: JSON with:

  * Extracted feature rows
  * Statistical summary
  * LLM analysis text

Example using Python:

```python
import requests

with open("file.pcap", "rb") as f:
    res = requests.post("http://localhost:5000/upload", files={"file": f})
    print(res.json())
```

## Future Work

* Build a frontend drag-and-drop UI to upload `.pcap` files.
* Train and evaluate ML classifiers using the extracted dataset.
* Add automatic label prediction via LLM + classifier.
* Extend feature set with timing/flow-level metadata.

---

This project serves as both a practical tool and an educational framework for understanding and detecting DNS tunneling using hybrid ML + LLM systems.

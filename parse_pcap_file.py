import pandas as pd
from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP
from collections import defaultdict
import math
from datetime import datetime

# --- Helper Functions ---
def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_features_from_pcap(pcap_file, label):
    packets = rdpcap(pcap_file)

    # Step 1: Compute average messages per minute and per second (once)
    timestamps = [pkt.time for pkt in packets]
    datetimes = [datetime.fromtimestamp(float(ts)) for ts in timestamps]
    df_temp = pd.DataFrame({'timestamp': datetimes})

    df_temp['minute'] = df_temp['timestamp'].dt.floor('min')
    df_temp['second'] = df_temp['timestamp'].dt.floor('s')

    message_counts_min = df_temp.groupby('minute').size().reset_index(name='messages_per_minute')
    message_counts_sec = df_temp.groupby('second').size().reset_index(name='messages_per_second')

    avg_per_minute = message_counts_min['messages_per_minute'].mean()
    avg_per_second = message_counts_sec['messages_per_second'].mean()

    # Step 2: Extract features from DNS packets
    data = []
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            qr_flag = dns.qr  # 0 for query, 1 for response
            src_ip_len = len(packet[IP].src)
            dst_ip_len = len(packet[IP].dst)

            if qr_flag == 0 and dns.qdcount > 0:
                query = dns.qd.qname.decode().rstrip('.') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)

                row = {
                    "direction": "0", # 0 is query, 1 is response
                    "domain_name": query,
                    "domain_length": len(query),
                    "subdomain_count": query.count('.'),
                    "entropy": round(shannon_entropy(query), 3),
                    "num_upper": sum(c.isupper() for c in query),
                    "num_lower": sum(c.islower() for c in query),
                    "num_digits": sum(c.isdigit() for c in query),
                    "num_special": sum(c in '-_=' for c in query),
                    "query_type": dns.qd.qtype,
                    "response_size": None,
                    "ttl": None,
                    "src_ip_len": src_ip_len,
                    "dst_ip_len": dst_ip_len,
                    "avg_msgs_per_min": round(avg_per_minute, 2),
                    "avg_msgs_per_sec": round(avg_per_second, 2),
                    "label": label
                }
                data.append(row)

            elif qr_flag == 1 and dns.ancount > 0:
                for i in range(dns.ancount):
                    answer = dns.an[i]
                    name = answer.rrname.decode().rstrip('.') if isinstance(answer.rrname, bytes) else str(answer.rrname)
                    rdata = answer.rdata
                    rdata_str = rdata.decode() if isinstance(rdata, bytes) else str(rdata)

                    row = {
                        "direction": "1", # 0 is query, 1 is response
                        "domain_name": name,
                        "domain_length": len(name),
                        "subdomain_count": name.count('.'),
                        "entropy": round(shannon_entropy(name), 3),
                        "num_upper": sum(c.isupper() for c in name),
                        "num_lower": sum(c.islower() for c in name),
                        "num_digits": sum(c.isdigit() for c in name),
                        "num_special": sum(c in '-_=' for c in name),
                        "query_type": answer.type,
                        "response_size": len(rdata_str),
                        "ttl": answer.ttl,
                        "src_ip_len": src_ip_len,
                        "dst_ip_len": dst_ip_len,
                        "avg_msgs_per_min": round(avg_per_minute, 2),
                        "avg_msgs_per_sec": round(avg_per_second, 2),
                        "label": label
                    }
                    data.append(row)

    return pd.DataFrame(data)


def print_dns_stats(df):
    print("\n🔍 Basic Stats:")
    print(f"Total DNS Queries: {len(df)}")
    print(f"Unique Queried Domains: {df['domain_name'].nunique()}")
    print(f"Distinct Source IPs: {df['src_ip_len'].nunique()}")
    print(f"Distinct Destination IPs: {df['dst_ip_len'].nunique()}")

    print("\n📦 Query Type Distribution:")
    print(df['query_type'].value_counts())

    print("\n📐 Domain Length Statistics:")
    print(df['domain_length'].describe())

    print("\n🔣 Entropy Statistics:")
    print(df['entropy'].describe())

    print("\n🔁 Response Size Statistics (non-null only):")
    print(df['response_size'].dropna().describe())

    print("\n⏱ TTL Statistics (non-null only):")
    print(df['ttl'].dropna().describe())

    print("\n📊 Label Distribution:")
    print(df['label'].value_counts())


# Run the feature extraction
label_input = "B"  # This should be changed to user input in real usage
pcap_path = "normal_00000_20230805150331.pcap"  # Replace with actual uploaded file path
df = extract_features_from_pcap(pcap_path, label_input)

# Show the first few rows
# pd.set_option('display.max_colwidth', None)
# pd.set_option('display.max_columns', None)
print(df.head(30))
# pd.reset_option('display.max_columns')
# pd.reset_option('display.max_columns')

# Save to CSV
df.to_csv("dns_features_labeled.csv", index=False)
print("Saved to dns_features_labeled.csv")

print_dns_stats(df)
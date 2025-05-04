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

# def extract_features_from_pcap(pcap_file, label):
#     packets = rdpcap(pcap_file)
#     packets = sorted(packets, key=lambda pkt: pkt.time)

#     # Step 1: Compute average messages per minute and per second (once)
#     timestamps = [pkt.time for pkt in packets]
#     datetimes = [datetime.fromtimestamp(float(ts)) for ts in timestamps]
#     df_temp = pd.DataFrame({'timestamp': datetimes})

#     df_temp['minute'] = df_temp['timestamp'].dt.floor('min')
#     df_temp['second'] = df_temp['timestamp'].dt.floor('s')

#     message_counts_min = df_temp.groupby('minute').size().reset_index(name='messages_per_minute')
#     message_counts_sec = df_temp.groupby('second').size().reset_index(name='messages_per_second')

#     avg_per_minute = message_counts_min['messages_per_minute'].mean()
#     avg_per_second = message_counts_sec['messages_per_second'].mean()

#     # Step 2: Extract features from DNS packets
#     data = []
#     for packet in packets:
#         if packet.haslayer(DNS) and packet.haslayer(IP):
#             dns = packet[DNS]
#             ip = packet[IP]
#             qr_flag = dns.qr  # 0 for query, 1 for response

#             if qr_flag == 0 and dns.qdcount > 0:
#                 domain_name = dns.qd.qname.decode().rstrip('.') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
#                 transaction_id = dns.id

#                 response_packet = find_dns_response_for_query_info(packets, domain_name, ip.src, ip.dst, transaction_id, packet.time)
#                 if response_packet:
#                     response_dns = response_packet[DNS]
#                     rdata_list = [str(ans.rdata) for ans in response_dns.an]
#                     avg_resp_domain_name_len = sum(len(rdata) for rdata in rdata_list) / len(rdata_list) if rdata_list else 0
#                     ttl_list = [ans.ttl for ans in response_dns.an]
#                     avg_resp_ttl = sum(ttl_list) / len(ttl_list) if ttl_list else 0
#                     response_size = len(response_packet)
#                 else:
#                     response_size = None
#                     avg_resp_domain_name_len = 0
#                     avg_resp_ttl = 0

#                 row = {
#                     "domain_length": len(domain_name),
#                     "subdomain_count": domain_name.count('.'),
#                     "entropy": round(shannon_entropy(domain_name), 3),
#                     "num_digits": sum(c.isdigit() for c in domain_name),
#                     "num_special": sum(c in '-_=' for c in domain_name),
#                     "query_type": dns.qd.qtype,
#                     "response_size": response_size,
#                     "avg_resp_domain_name_len": round(avg_resp_domain_name_len, 2),
#                     "avg_resp_ttl": round(avg_resp_ttl, 2),
#                     "src_ip_len": len(ip.src),
#                     "dst_ip_len": len(ip.dst),
#                     "avg_msgs_per_min": round(avg_per_minute, 2),
#                     "avg_msgs_per_sec": round(avg_per_second, 2),
#                     "label": label
#                 }
#                 data.append(row)

#             elif qr_flag == 1 and dns.ancount > 0:
#                 continue  # Skip responses for now

#     return pd.DataFrame(data)


def extract_features_from_pcap(pcap_file, label):
    packets = rdpcap(pcap_file)
    packets = sorted(packets, key=lambda pkt: pkt.time)

    # Step 1: Compute message rates
    timestamps = [pkt.time for pkt in packets]
    datetimes = [datetime.fromtimestamp(float(ts)) for ts in timestamps]
    df_temp = pd.DataFrame({'timestamp': datetimes})
    df_temp['minute'] = df_temp['timestamp'].dt.floor('min')
    df_temp['second'] = df_temp['timestamp'].dt.floor('s')
    avg_per_minute = df_temp.groupby('minute').size().mean()
    avg_per_second = df_temp.groupby('second').size().mean()

    # Step 2: Index DNS responses for fast lookup
    response_index = index_dns_responses(packets)

    # Step 3: Extract query features + match response
    data = []
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            ip = packet[IP]

            if dns.qr == 0 and dns.qdcount > 0:  # Query
                try:
                    domain_name = dns.qd.qname.decode("utf-8").rstrip('.') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                except UnicodeDecodeError:
                    try: 
                        domain_name = dns.qd.qname.decode("latin1").rstrip('.') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    except Exception:
                        print(f"Error decoding domain name: {dns.qd.qname}")
                        continue
                tx_id = dns.id
                timestamp = packet.time

                key = (tx_id, ip.dst, ip.src)  # reverse direction for response
                matching_packets = response_index.get(key, [])

                response_packet = None
                for resp in matching_packets:
                    try:
                        for answer in resp[DNS].an:
                            answer_name = answer.rrname.decode().rstrip('.') if isinstance(answer.rrname, bytes) else str(answer.rrname)
                            if answer_name == domain_name and resp.time >= timestamp:
                                response_packet = resp
                                break
                        if response_packet:
                            break
                    except Exception:
                        continue

                # Extract response features if matched
                if response_packet:
                    answers = response_packet[DNS].an
                    rdata_list = []
                    for ans in answers: 
                        if ans.type == 15:  # MX record
                            rdata_list.append(str(ans.rrname))
                        else:
                            rdata_list.append(str(ans.rdata))
                    ttl_list = [ans.ttl for ans in answers]
                    avg_resp_domain_name_len = sum(len(r) for r in rdata_list) / len(rdata_list) if rdata_list else 0
                    avg_resp_ttl = sum(ttl_list) / len(ttl_list) if ttl_list else 0
                    response_size = len(response_packet)
                else:
                    avg_resp_domain_name_len = 0
                    avg_resp_ttl = 0
                    response_size = None

                # Append features
                row = {
                    "domain_length": len(domain_name),
                    "subdomain_count": domain_name.count('.'),
                    "entropy": round(shannon_entropy(domain_name), 3),
                    "num_digits": sum(c.isdigit() for c in domain_name),
                    "num_special": sum(c in '-_=' for c in domain_name),
                    "query_type": dns.qd.qtype,
                    "response_size": response_size,
                    "avg_resp_domain_name_len": round(avg_resp_domain_name_len, 2),
                    "avg_resp_ttl": round(avg_resp_ttl, 2),
                    "src_ip_len": len(ip.src),
                    "dst_ip_len": len(ip.dst),
                    "avg_msgs_per_min": round(avg_per_minute, 2),
                    "avg_msgs_per_sec": round(avg_per_second, 2),
                    "label": label
                }
                data.append(row)

    return pd.DataFrame(data)


def index_dns_responses(packets):
    response_index = {}
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            ip = packet[IP]
            if dns.qr == 1:  # response
                tx_id = dns.id
                key = (tx_id, ip.src, ip.dst)
                response_index.setdefault(key, []).append(packet)
    return response_index


def find_dns_response_for_query_info(packets, query_name, src_ip, dst_ip, tx_id, timestamp):
    for i, packet in enumerate(packets):
        if not (packet.haslayer(DNS) and packet.haslayer(IP)):
            continue

        dns = packet[DNS]
        ip = packet[IP]

        if dns.qr == 1 and dns.id == tx_id:
            # IPs are reversed in response
            if ip.src == dst_ip and ip.dst == src_ip:
                try:
                    # Some responses contain multiple answers
                    for answer in dns.an:
                        ans_name = answer.rrname.decode().rstrip('.') if isinstance(answer.rrname, bytes) else str(answer.rrname)
                        if ans_name == query_name and packet.time >= timestamp:
                            return packet
                except Exception:
                    continue

    return None



def print_dns_stats(df):
    print("\n🔍 Basic Stats:")
    print(f"Total DNS Queries: {len(df)}")

    print("\n📦 Query Type Distribution:")
    print(df['query_type'].value_counts())

    print("\n📐 Domain Length Statistics:")
    print(df['domain_length'].describe())

    print("\n🔣 Entropy Statistics:")
    print(df['entropy'].describe())

    print("\n🔁 Response Size Statistics (non-null only):")
    print(df['response_size'].dropna().describe())

    print("\n📊 Label Distribution:")
    print(df['label'].value_counts())


# Run the feature extraction
label_input = "B"  # This should be changed to user input in real usage
pcap_path = "normal_00000_20230805150331.pcap"  # Replace with actual uploaded file path
df = extract_features_from_pcap(pcap_path, label_input)

# Show the first few rows
# pd.set_option('display.max_colwidth', None)
pd.set_option('display.max_columns', None)
print(df.head(30))
# pd.reset_option('display.max_columns')
pd.reset_option('display.max_columns')

# Save to CSV
df.to_csv("dns_features_labeled.csv", index=False)
print("Saved to dns_features_labeled.csv")

print_dns_stats(df)
import argparse
import os
import pandas as pd
from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP
from collections import defaultdict
import math
from datetime import datetime


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


def index_dns_responses(packets):
    response_index = {}
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            ip = packet[IP]
            if dns.qr == 1:
                tx_id = dns.id
                key = (tx_id, ip.src, ip.dst)
                response_index.setdefault(key, []).append(packet)
    return response_index


def extract_features_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    packets = sorted(packets, key=lambda pkt: pkt.time)

    timestamps = [pkt.time for pkt in packets]
    datetimes = [datetime.fromtimestamp(float(ts)) for ts in timestamps]
    df_temp = pd.DataFrame({'timestamp': datetimes})
    df_temp['minute'] = df_temp['timestamp'].dt.floor('min')
    df_temp['second'] = df_temp['timestamp'].dt.floor('s')
    avg_per_minute = df_temp.groupby('minute').size().mean()
    avg_per_second = df_temp.groupby('second').size().mean()

    response_index = index_dns_responses(packets)

    data = []
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            ip = packet[IP]

            if dns.qr == 0 and dns.qdcount > 0:
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

                key = (tx_id, ip.dst, ip.src)
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

                if response_packet:
                    answers = response_packet[DNS].an
                    rdata_list = []
                    for ans in answers:
                        if ans.type in (15, 33, 46):
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
                }
                data.append(row)

    return pd.DataFrame(data)


def main():
    parser = argparse.ArgumentParser(description="Extract DNS features from a PCAP file.")
    parser.add_argument("-p", "--path", help="Path to the input PCAP file.", required=True)
    parser.add_argument("-o", "--output", default="dns_features.csv", help="CSV file to store the output data.")
    args = parser.parse_args()

    df = extract_features_from_pcap(args.path)
    df.to_csv(args.output, index=False)
    print(f"\n✅ Features saved to {args.output}")


if __name__ == "__main__":
    main()

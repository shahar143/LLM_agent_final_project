import argparse
import os
import statistics
from collections import defaultdict
from datetime import datetime

import pandas as pd
from scapy.all import rdpcap, TCP, IP

def extract_tls_flow_features(pcap_file):
    pcap = rdpcap(pcap_file)
    flows = defaultdict(list)

    for pkt in pcap:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]

            fwd = (ip.src, ip.dst, tcp.sport, tcp.dport)
            rev = (ip.dst, ip.src, tcp.dport, tcp.sport)
            key = fwd if fwd in flows else rev
            flows[key].append(pkt)

    flow_data = []

    for (src_ip, dst_ip, src_port, dst_port), packets in flows.items():
        if src_port != 443 and dst_port != 443:
            continue

        timestamps = [float(pkt.time) for pkt in packets]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.000001
        first_timestamp = datetime.fromtimestamp(min(timestamps))

        bytes_sent = 0
        bytes_received = 0
        pkt_lengths = []

        for pkt in packets:
            ip = pkt[IP]
            pkt_len = len(pkt)
            pkt_lengths.append(pkt_len)

            if ip.src == src_ip and ip.dst == dst_ip:
                bytes_sent += pkt_len
            elif ip.src == dst_ip and ip.dst == src_ip:
                bytes_received += pkt_len

        sent_rate = bytes_sent / duration
        recv_rate = bytes_received / duration

        mean_len = statistics.mean(pkt_lengths)
        median_len = statistics.median(pkt_lengths)
        mode_len = statistics.mode(pkt_lengths) if len(set(pkt_lengths)) < len(pkt_lengths) else pkt_lengths[0]
        std_len = statistics.stdev(pkt_lengths) if len(pkt_lengths) > 1 else 0
        var_len = statistics.variance(pkt_lengths) if len(pkt_lengths) > 1 else 0
        skew_median_len = (mean_len - median_len) / std_len if std_len != 0 else 0
        skew_mode_len = (mean_len - mode_len) / std_len if std_len != 0 else 0
        coef_var_len = std_len / mean_len if mean_len != 0 else 0

        timestamps_sorted = sorted(timestamps)
        inter_arrival_times = [
            t2 - t1 for t1, t2 in zip(timestamps_sorted[:-1], timestamps_sorted[1:])
        ]

        if inter_arrival_times:
            mean_time = statistics.mean(inter_arrival_times)
            median_time = statistics.median(inter_arrival_times)
            mode_time = statistics.mode(inter_arrival_times) if len(set(inter_arrival_times)) < len(inter_arrival_times) else inter_arrival_times[0]
            std_time = statistics.stdev(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
            var_time = statistics.variance(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
            skew_median_time = (mean_time - median_time) / std_time if std_time != 0 else 0
            skew_mode_time = (mean_time - mode_time) / std_time if std_time != 0 else 0
            coef_var_time = std_time / mean_time if mean_time != 0 else 0
        else:
            mean_time = median_time = mode_time = std_time = var_time = 0
            skew_median_time = skew_mode_time = coef_var_time = 0

        response_times = []
        sorted_pkts = sorted(packets, key=lambda p: p.time)

        for i in range(len(sorted_pkts) - 1):
            p1 = sorted_pkts[i]
            p2 = sorted_pkts[i + 1]

            if IP in p1 and IP in p2:
                ip1 = p1[IP]
                ip2 = p2[IP]

                if (ip1.src == src_ip and ip1.dst == dst_ip) and (ip2.src == dst_ip and ip2.dst == src_ip):
                    resp_time = float(p2.time) - float(p1.time)
                    if resp_time > 0:
                        response_times.append(resp_time)

        if response_times:
            mean_resp = statistics.mean(response_times)
            median_resp = statistics.median(response_times)
            mode_resp = statistics.mode(response_times) if len(set(response_times)) < len(response_times) else response_times[0]
            std_resp = statistics.stdev(response_times) if len(response_times) > 1 else 0
            var_resp = statistics.variance(response_times) if len(response_times) > 1 else 0
            skew_median_resp = (mean_resp - median_resp) / std_resp if std_resp != 0 else 0
            skew_mode_resp = (mean_resp - mode_resp) / std_resp if std_resp != 0 else 0
            coef_var_resp = std_resp / mean_resp if mean_resp != 0 else 0
        else:
            mean_resp = median_resp = mode_resp = std_resp = var_resp = 0
            skew_median_resp = skew_mode_resp = coef_var_resp = 0

        flow_data.append({
            "SourceIP": src_ip,
            "DestinationIP": dst_ip,
            "SourcePort": src_port,
            "DestinationPort": dst_port,
            "TimeStamp": first_timestamp,
            "Duration": duration,
            "FlowBytesSent": bytes_sent,
            "FlowSentRate": sent_rate,
            "FlowBytesReceived": bytes_received,
            "FlowReceivedRate": recv_rate,
            "PacketLengthVariance": var_len,
            "PacketLengthStandardDeviation": std_len,
            "PacketLengthMean": mean_len,
            "PacketLengthMedian": median_len,
            "PacketLengthMode": mode_len,
            "PacketLengthSkewFromMedian": skew_median_len,
            "PacketLengthSkewFromMode": skew_mode_len,
            "PacketLengthCoefficientofVariation": coef_var_len,
            "PacketTimeVariance": var_time,
            "PacketTimeStandardDeviation": std_time,
            "PacketTimeMean": mean_time,
            "PacketTimeMedian": median_time,
            "PacketTimeMode": mode_time,
            "PacketTimeSkewFromMedian": skew_median_time,
            "PacketTimeSkewFromMode": skew_mode_time,
            "PacketTimeCoefficientofVariation": coef_var_time,
            "ResponseTimeVariance": var_resp,
            "ResponseTimeStandardDeviation": std_resp,
            "ResponseTimeMean": mean_resp,
            "ResponseTimeMedian": median_resp,
            "ResponseTimeMode": mode_resp,
            "ResponseTimeSkewFromMedian": skew_median_resp,
            "ResponseTimeSkewFromMode": skew_mode_resp,
            "ResponseTimeTimeCoefficientofVariation": coef_var_resp
        })

    return pd.DataFrame(flow_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract TLS flow features from a PCAP file.")
    parser.add_argument("-p", "--pcap", required=True, help="Path to the input PCAP file")
    parser.add_argument("-o", "--output", help="Optional path to save the output CSV file")

    args = parser.parse_args()
    df = extract_tls_flow_features(args.pcap)

    print(f"✅ Extracted {len(df)} TLS flows")

    if args.output:
        df.to_csv(args.output, index=False)
        print(f"📄 Saved features to: {os.path.abspath(args.output)}")
    else:
        print(df.head())

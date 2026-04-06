import math
from collections import Counter


class FeatureExtractor:

    def extract_features(self, flows, all_packets):
        return [self.extract_flow_features(flow, all_packets) for flow in flows]

    def extract_flow_features(self, flow, all_packets):

        packets = flow["packets"]

        fwd_packets = [p for p in packets if p["srcIP"] == flow["srcIP"]]
        bwd_packets = [p for p in packets if p["srcIP"] == flow["dstIP"]]

        flow_duration = max(1, (flow["endTime"] - flow["startTime"]) * 1000000)

        # Packet lengths
        fwd_lengths = [p["length"] for p in fwd_packets]
        bwd_lengths = [p["length"] for p in bwd_packets]
        all_lengths = [p["length"] for p in packets]

        # timestamps
        timestamps = sorted([p["timestamp"] for p in packets])
        fwd_timestamps = sorted([p["timestamp"] for p in fwd_packets])
        bwd_timestamps = sorted([p["timestamp"] for p in bwd_packets])

        all_iat = self.calculate_iat(timestamps)
        fwd_iat = self.calculate_iat(fwd_timestamps)
        bwd_iat = self.calculate_iat(bwd_timestamps)

        # TCP flags
        syn_count = sum(1 for p in packets if p["tcpFlags"]["syn"])
        ack_count = sum(1 for p in packets if p["tcpFlags"]["ack"])
        fin_count = sum(1 for p in packets if p["tcpFlags"]["fin"])
        rst_count = sum(1 for p in packets if p["tcpFlags"]["rst"])
        psh_count = sum(1 for p in packets if p["tcpFlags"]["psh"])
        urg_count = sum(1 for p in packets if p["tcpFlags"]["urg"])

        payload_sizes = [p["payloadSize"] for p in packets]
        total_payload = sum(payload_sizes)

        header_sizes = [p["headerSize"] for p in packets]

        ttls = [p["ttl"] for p in packets if p.get("ttl") is not None]

        flow_bytes_per_sec = (
            sum(all_lengths) / (flow_duration / 1000000)
            if flow_duration > 0 else 0
        )

        flow_packets_per_sec = (
            len(packets) / (flow_duration / 1000000)
            if flow_duration > 0 else 0
        )

        return {
            "flowDuration": flow_duration,
            "totalFwdPackets": len(fwd_packets),
            "totalBwdPackets": len(bwd_packets),
            "totalPackets": len(packets),

            "fwdPacketLengthMin": min(fwd_lengths) if fwd_lengths else 0,
            "fwdPacketLengthMax": max(fwd_lengths) if fwd_lengths else 0,
            "fwdPacketLengthMean": self.mean(fwd_lengths),
            "fwdPacketLengthStd": self.std(fwd_lengths),

            "bwdPacketLengthMin": min(bwd_lengths) if bwd_lengths else 0,
            "bwdPacketLengthMax": max(bwd_lengths) if bwd_lengths else 0,
            "bwdPacketLengthMean": self.mean(bwd_lengths),
            "bwdPacketLengthStd": self.std(bwd_lengths),

            "packetLengthMin": min(all_lengths) if all_lengths else 0,
            "packetLengthMax": max(all_lengths) if all_lengths else 0,
            "packetLengthMean": self.mean(all_lengths),
            "packetLengthStd": self.std(all_lengths),
            "packetLengthVariance": self.variance(all_lengths),

            "flowBytesPerSec": flow_bytes_per_sec,
            "flowPacketsPerSec": flow_packets_per_sec,
            "fwdPacketsPerSec": len(fwd_packets)/(flow_duration/1000000) if flow_duration else 0,
            "bwdPacketsPerSec": len(bwd_packets)/(flow_duration/1000000) if flow_duration else 0,

            "flowIATMean": self.mean(all_iat),
            "flowIATStd": self.std(all_iat),
            "flowIATMax": max(all_iat) if all_iat else 0,
            "flowIATMin": min(all_iat) if all_iat else 0,

            "fwdIATTotal": sum(fwd_iat),
            "fwdIATMean": self.mean(fwd_iat),
            "fwdIATStd": self.std(fwd_iat),
            "fwdIATMax": max(fwd_iat) if fwd_iat else 0,
            "fwdIATMin": min(fwd_iat) if fwd_iat else 0,

            "bwdIATTotal": sum(bwd_iat),
            "bwdIATMean": self.mean(bwd_iat),
            "bwdIATStd": self.std(bwd_iat),
            "bwdIATMax": max(bwd_iat) if bwd_iat else 0,
            "bwdIATMin": min(bwd_iat) if bwd_iat else 0,

            "finFlagCount": fin_count,
            "synFlagCount": syn_count,
            "rstFlagCount": rst_count,
            "pshFlagCount": psh_count,
            "ackFlagCount": ack_count,
            "urgFlagCount": urg_count,

            "synFlagRatio": syn_count/len(packets) if packets else 0,
            "ackFlagRatio": ack_count/len(packets) if packets else 0,
            "finFlagRatio": fin_count/len(packets) if packets else 0,

            "avgHeaderLength": self.mean(header_sizes),

            "totalPayloadBytes": total_payload,
            "avgPayloadSize": self.mean(payload_sizes),

            "sourceIPEntropy": self.calculate_entropy([p["srcIP"] for p in all_packets]),
            "destIPEntropy": self.calculate_entropy([p["dstIP"] for p in all_packets]),
            "sourcePortEntropy": self.calculate_entropy([str(p["srcPort"]) for p in all_packets]),
            "destPortEntropy": self.calculate_entropy([str(p["dstPort"]) for p in all_packets]),

            "downUpRatio": len(bwd_packets)/len(fwd_packets) if fwd_packets else 0,
            "averagePacketSize": total_payload/len(packets) if packets else 0,

            "minTTL": min(ttls) if ttls else 0,
            "maxTTL": max(ttls) if ttls else 0,
            "avgTTL": self.mean(ttls),

            "synToTotalRatio": syn_count/len(packets) if packets else 0,
            "smallPacketRatio": sum(1 for p in packets if p["length"] < 100) / max(1,len(packets)),
            "flowAsymmetry": abs(len(fwd_packets)-len(bwd_packets)) / max(1,len(packets))
        }

    def calculate_iat(self, timestamps):
        if len(timestamps) < 2:
            return []

        return [
            (timestamps[i] - timestamps[i - 1]) * 1000000
            for i in range(1, len(timestamps))
        ]

    def mean(self, arr):
        return sum(arr) / len(arr) if arr else 0

    def std(self, arr):
        if not arr:
            return 0
        m = self.mean(arr)
        return math.sqrt(sum((x - m) ** 2 for x in arr) / len(arr))

    def variance(self, arr):
        if not arr:
            return 0
        m = self.mean(arr)
        return sum((x - m) ** 2 for x in arr) / len(arr)

    def calculate_entropy(self, items):
        if not items:
            return 0

        counts = Counter(items)
        total = len(items)

        entropy = 0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

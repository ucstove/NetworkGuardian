import csv

# Import Scapy's packet-capture function and the protocol layers whose metadata
# is written to the CSV.
from scapy.all import Dot11, Ether, IP, IPv6, TCP, UDP, Packet, sniff

# Replace this placeholder with the interface name recognized by your OS.
INTERFACE = "YOUR_INTERFACE_NAME"
# Stop after this many packets.
MAX_PACKETS = 10000
CSV_FILE = "packets.csv"
CSV_FIELDS = [
    "timestamp",
    "length_bytes",
    "layers",
    "src_mac",
    "dst_mac",
    "wifi_type",
    "wifi_subtype",
    "wifi_addr1",
    "wifi_addr2",
    "wifi_addr3",
    "wifi_addr4",
    "src_ip",
    "dst_ip",
    "ip_protocol",
    "transport",
    "src_port",
    "dst_port",
]


def packet_to_csv_row(packet: Packet) -> dict[str, str | int]:
    """Extract selected packet metadata; packet payloads are not included."""
    # Initialize every column so all CSV rows have the same shape.
    row: dict[str, str | int] = {
        "timestamp": str(packet.time),
        "length_bytes": len(packet),
        # Record decoded layer names, not the contents of those layers.
        "layers": "|".join(layer.__name__ for layer in packet.layers()),
    }

    # Add Wi-Fi frame addressing when Scapy decoded an 802.11 layer.
    if packet.haslayer(Dot11):
        wifi = packet[Dot11]
        row.update(
            {
                "wifi_type": wifi.type,
                "wifi_subtype": wifi.subtype,
                "wifi_addr1": wifi.addr1 or "",
                "wifi_addr2": wifi.addr2 or "",
                "wifi_addr3": wifi.addr3 or "",
                "wifi_addr4": wifi.addr4 or "",
            }
        )

    # Add Ethernet MAC addresses when present.
    if packet.haslayer(Ether):
        ethernet = packet[Ether]
        row.update({"src_mac": ethernet.src, "dst_mac": ethernet.dst})

    # Add IP addresses and the IP protocol/next-header number.
    if packet.haslayer(IP):
        ip = packet[IP]
        row.update(
            {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ip_protocol": ip.proto,
            }
        )
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        row.update(
            {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ip_protocol": ip.nh,
            }
        )

    # Record transport ports when Scapy decoded TCP or UDP.
    if packet.haslayer(TCP):
        transport = packet[TCP]
        row.update(
            {
                "transport": "TCP",
                "src_port": transport.sport,
                "dst_port": transport.dport,
            }
        )
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        row.update(
            {
                "transport": "UDP",
                "src_port": transport.sport,
                "dst_port": transport.dport,
            }
        )

    return row


def main() -> None:
    """Capture up to MAX_PACKETS and write one metadata row per packet."""
    # Fail clearly if the interface placeholder has not been configured.
    if INTERFACE == "YOUR_INTERFACE_NAME":
        raise RuntimeError("Set INTERFACE to your capture interface first.")

    print(f"Capturing on {INTERFACE}; writing up to {MAX_PACKETS} rows to {CSV_FILE}.")

    # Open the CSV once, write its header, and stream each packet's metadata
    # directly to a row instead of retaining captured packets in memory.
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()

        def write_packet(packet: Packet) -> None:
            writer.writerow(packet_to_csv_row(packet))

        sniff(
            iface=INTERFACE,
            prn=write_packet,
            store=False,
            count=MAX_PACKETS,
        )

    print(f"Capture saved to {CSV_FILE}.")


# Run main() only when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()
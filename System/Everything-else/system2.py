import csv

# Import Scapy's packet-capture function and the protocol layers whose metadata
# is written to the CSV. RadioTap is required for RSSI; Dot11 is required for
# the 802.11-specific fields called out in SRS 4.2.1 (sequence number, duration,
# retry/protected flags).
from scapy.all import Dot11, RadioTap, Ether, IP, IPv6, TCP, UDP, Packet, sniff

# Replace this placeholder with the interface name recognized by your OS.
# For this project, this should be your ALFA adapter's monitor-mode interface
# (e.g. "wlan1") -- confirm the exact name with `iw dev` before running, since
# airmon-ng does not reliably rename this adapter's interface to "wlan1mon".
INTERFACE = "YOUR_INTERFACE_NAME"
# Stop after this many packets.
MAX_PACKETS = 10000
CSV_FILE = "packets.csv"
CSV_FIELDS = [
    "timestamp",
    "inter_frame_delta",
    "length_bytes",
    "layers",
    "frame_type",
    "frame_subtype",
    "duration",
    "seq_num",
    "retry",
    "protected",
    "rssi_dbm",
    "src_mac",
    "dst_mac",
    "bssid",
    "src_ip",
    "dst_ip",
    "ip_protocol",
    "transport",
    "src_port",
    "dst_port",
]

# Frame Control flag bitmasks (IEEE 802.11 Frame Control field, byte order as
# decoded by Scapy's Dot11.FCfield).
_FC_TO_DS = 0x01
_FC_FROM_DS = 0x02
_FC_RETRY = 0x08
_FC_PROTECTED = 0x40

# Tracks the timestamp of the previously captured packet so inter_frame_delta
# (a per-packet field required by SRS 4.2.1) can be computed. Module-level
# state is acceptable here since sniff() calls write_packet() sequentially
# from a single thread.
_last_timestamp: float | None = None


def _resolve_wifi_addresses(wifi: Packet) -> tuple[str, str, str | None]:
    """Resolve (src_mac, dst_mac, bssid) from Dot11 addr1-4 using the
    ToDS/FromDS flags, since 802.11 does not fix "addr1 = source" the way
    Ethernet does. Assumes standard infrastructure mode; in WDS mode
    (ToDS and FromDS both set) there is no single BSSID field, so bssid
    is returned as None.
    """
    fc = int(wifi.FCfield)
    to_ds = bool(fc & _FC_TO_DS)
    from_ds = bool(fc & _FC_FROM_DS)

    if not to_ds and not from_ds:
        # AP/ad-hoc -> station, or station -> station in an IBSS.
        dst, src, bssid = wifi.addr1, wifi.addr2, wifi.addr3
    elif to_ds and not from_ds:
        # Station -> AP.
        bssid, src, dst = wifi.addr1, wifi.addr2, wifi.addr3
    elif not to_ds and from_ds:
        # AP -> station.
        dst, bssid, src = wifi.addr1, wifi.addr2, wifi.addr3
    else:
        # WDS (AP -> AP): addr1=RA, addr2=TA, addr3=DA, addr4=SA.
        dst, src, bssid = wifi.addr3, wifi.addr4, None

    return src or "", dst or "", bssid or ""


def packet_to_csv_row(packet: Packet) -> dict[str, str | int | float]:
    """Extract selected packet metadata; packet payloads are not included."""
    global _last_timestamp

    timestamp = float(packet.time)
    inter_frame_delta = (
        timestamp - _last_timestamp if _last_timestamp is not None else 0.0
    )
    _last_timestamp = timestamp

    # Initialize every column so all CSV rows have the same shape.
    row: dict[str, str | int | float] = {
        "timestamp": str(packet.time),
        "inter_frame_delta": round(inter_frame_delta, 6),
        "length_bytes": len(packet),
        # Record decoded layer names, not the contents of those layers.
        "layers": "|".join(layer.__name__ for layer in packet.layers()),
    }

    # Add RSSI when Scapy decoded a RadioTap header (present whenever the
    # capture interface is in monitor mode with RadioTap headers enabled).
    if packet.haslayer(RadioTap):
        radiotap = packet[RadioTap]
        rssi = getattr(radiotap, "dBm_AntSignal", None)
        if rssi is not None:
            row["rssi_dbm"] = rssi

    # Add Wi-Fi frame addressing/flags when Scapy decoded an 802.11 layer.
    if packet.haslayer(Dot11):
        wifi = packet[Dot11]
        src_mac, dst_mac, bssid = _resolve_wifi_addresses(wifi)
        fc = int(wifi.FCfield)
        row.update(
            {
                "frame_type": wifi.type,
                "frame_subtype": wifi.subtype,
                "duration": wifi.ID,
                # SC is 16 bits: top 12 bits are the sequence number, bottom
                # 4 bits are the fragment number.
                "seq_num": wifi.SC >> 4,
                "retry": int(bool(fc & _FC_RETRY)),
                "protected": int(bool(fc & _FC_PROTECTED)),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "bssid": bssid,
            }
        )
    elif packet.haslayer(Ether):
        # Fallback for the (unlikely, for this project) case this script is
        # ever pointed at a wired interface instead of the monitor-mode
        # Wi-Fi adapter.
        ethernet = packet[Ether]
        row.update({"src_mac": ethernet.src, "dst_mac": ethernet.dst})

    # Add IP addresses and the IP protocol/next-header number. Note: on a
    # WPA2-AES network, Scapy generally cannot decrypt 802.11 payloads, so
    # these fields will be empty for nearly all captured frames -- that is
    # expected, not a bug.
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
            # Optional: uncomment and set to your AP's BSSID to drop frames
            # from neighboring networks on the same channel before they ever
            # reach Python -- mirrors the "filters to the testbed" behavior
            # described for PacketSniffer in the HLD, and reduces CPU load
            # from channel noise.
            # filter="wlan addr3 AA:BB:CC:DD:EE:FF",
        )

    print(f"Capture saved to {CSV_FILE}.")


# Run main() only when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()

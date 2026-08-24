from scapy.all import sniff, conf

INTERFACE = 54

print("Starting WSL packet capture...")
print("Interface index:", INTERFACE)
print("Waiting for packets...")
print("Press Ctrl+C to stop.\n")


def show_packet(packet):
    print(f"PACKET: {packet.summary()} | {len(packet)} bytes")


try:
    iface = conf.ifaces.dev_from_index(INTERFACE)

    print("Using interface:")
    print(iface)
    print()

    sniff(
        iface=iface,
        prn=show_packet,
        store=False
    )

except Exception as e:
    print("\nCAPTURE ERROR:")
    print(e)
import sys
import signal
from scapy.all import *
from scapy.layers.inet import TCP, IP


def tcp_port_scan(target, ports):
    for port in ports:
        tcp_packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(tcp_packet, timeout=2, verbose=0)

        if (
            response is not None
            and response.haslayer(TCP)
            and response.getlayer(TCP).flags == 0x12
        ):
            print(f"Port {port} is open on {target}")
        else:
            print(f"Port {port} is closed on {target}")


def signal_handler(signal, frame):
    print("\nProgram stopped by user")
    sys.exit(0)


if __name__ == "__main__":
    target = sys.argv[1]
    ports = range(1, 1025)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        tcp_port_scan(target, ports)
    except KeyboardInterrupt:
        print("\nProgram stopped by user")

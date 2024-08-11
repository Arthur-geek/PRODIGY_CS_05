#!pip install scapy tabulate
from scapy.all import sniff, IP, TCP, UDP, wrpcap, rdpcap
import argparse
from tabulate import tabulate

def packet_callback(packet):
    packet_data = {
        "Source IP": packet[IP].src if IP in packet else None,
        "Destination IP": packet[IP].dst if IP in packet else None,
        "Protocol": packet.sprintf("%IP.proto%"),
        "Source Port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
        "Destination Port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
        "Payload": bytes(packet[TCP].payload if TCP in packet else (packet[UDP].payload if UDP in packet else b'')),
    }
    # create a table with keys as hearder
    print(tabulate([packet_data], headers="keys"))
    
    # function to save the capture
def save_packets(packets, filename):
    wrpcap(filename, packets)
    print(f"Packets saved to {filename}")
    
    # if you want to analyze one capture this function permit to read it
def load_packets(filename):
    packets = rdpcap(filename)
    return packets

def main():
    
    parser = argparse.ArgumentParser(description='Advanced Packet Sniffer')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    parser.add_argument('--filter', type=str, help='BPF filter for packet capture')
    parser.add_argument('--output', type=str, help='File to save captured packets')
    parser.add_argument('--input', type=str, help='File to read packets from')
    args = parser.parse_args()

    # verify if the user want to analyse an existence capture or no .
    if args.input:
        packets = load_packets(args.input)
        for packet in packets:
            packet_callback(packet)
    else:
        packets = sniff( prn=packet_callback, count=args.count, filter=args.filter)
        print("Packet capture finished.")
        # check if the user provide a output name to save the network traffic packet
        if args.output:
            save_packets(packets, args.output)

if __name__ == '__main__':
    main()
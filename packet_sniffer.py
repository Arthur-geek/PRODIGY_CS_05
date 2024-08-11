from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import keyboard  # To listen for keyboard events

# Log file path
log_file = "packet_log.pcap"
running = True  # Flag to control the sniffing process

def packet_callback(packet):
    """
    Callback function to process each captured packet and save details to a file.

    Parameters:
    - packet: The captured network packet.
    """
    global running
    if not running:
        return  # Stop processing packets if the flag is False

    with open(log_file, "a") as f:
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            if TCP in packet:
                protocol = "TCP"
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                protocol = "UDP"
                payload = bytes(packet[UDP].payload)
            else:
                payload = b""
            
            f.write(f"Packet: {protocol} | {src_ip} -> {dst_ip}\n")
            f.write(f"Payload: {payload}\n\n")

def on_key_event(event):
    """
    Callback function to handle key events.

    Parameters:
    - event: The keyboard event.
    """
    global running
    if event.name == 'esc':
        print("Escape key pressed. Stopping packet sniffer...")
        running = False

def main():
    """
    Main function to start the packet sniffer and key listener.
    """
    print("Starting packet sniffer... Logging to", log_file)
    
    # Start listening for key events
    keyboard.on_press(on_key_event)

    # Start packet sniffing
    sniff(prn=packet_callback, store=False)

    # Unregister the key event listener when done
    keyboard.unhook_all()

if __name__ == "__main__":
    main()

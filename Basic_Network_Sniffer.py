from scapy.all import sniff   # Provides tools for network packet manipulation and sniffing.
import netifaces              # Helps retrieve information about network interfaces.

def list_interfaces():
    ifaces = netifaces.interfaces()
    print("Available interfaces:")
    for iface in ifaces:
        print(f"- {iface}")

def packet_callBack(packet):
    print(packet.show())

def main():
    list_interfaces()
    interface = input("Enter the interface to sniff: ")
    count = int(input("Number of packets to sniff(0 --> capture infinitely): "))
    
    sniff(prn=packet_callBack, iface=interface, count=count)

if __name__ == "__main__":
    main()


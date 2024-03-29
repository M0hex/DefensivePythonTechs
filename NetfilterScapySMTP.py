import os
from netfilterqueue import NetfilterQueue
from scapy.all import *


def modify_ehlo_response(pkt):
    try:
        packet = IP(pkt.get_payload())

        if packet.haslayer(TCP) and packet[TCP].dport == 25 and packet.haslayer(Raw):
            raw_load = packet[Raw].load

            # Check if the packet contains an EHLO request
            if b"EHLO" in raw_load:
                # Modify EHLO response according to your requirements
                modified_response = b"250-mail.example.com | PIPELINING | SIZE 10240000 | VRFY | ETRN | AUTH PLAIN LOGIN | ENHANCEDSTATUSCODES | 8BITMIME | DSN | SMTPUTF8 | CHUNKING\r\n"

                # Construct the new packet with modified response
                new_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                             TCP(dport=packet[TCP].sport, sport=packet[TCP].dport,
                                 seq=packet[TCP].ack, ack=packet[TCP].seq + len(raw_load),
                                 flags="PA") / \
                             Raw(load=modified_response)

                # Send the modified packet
                send(new_packet, verbose=False)

                # Drop the original EHLO response
                pkt.drop()
            else:
                pkt.accept()  # Accept other packets
        else:
            pkt.accept()  # Accept non-SMTP packets
    except Exception as e:
        print("An error occurred:", e)
        pkt.accept()  # Accept packet in case of an error


def main():
    # Set up iptables rules to redirect SMTP traffic to netfilterqueue
    os.system("iptables -I OUTPUT -p tcp --dport 25 -j NFQUEUE --queue-num 1")
    os.system("iptables -I INPUT -p tcp --dport 25 -j NFQUEUE --queue-num 1")

    # Create netfilterqueue object and bind it to queue number 1
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_ehlo_response)

    try:
        print("[+] Waiting for EHLO requests...")
        nfqueue.run()  # Run indefinitely until KeyboardInterrupt
    except KeyboardInterrupt:
        print("[-] Exiting...")
        nfqueue.unbind()

    # Remove iptables rules after exiting
    os.system("iptables --flush")
  


if __name__ == "__main__":
    main()

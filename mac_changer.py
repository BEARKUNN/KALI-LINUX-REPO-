#!/usr/bin/env python

import subprocess
import optparse
import re


# (get_argument is where you get to make cmd friendly sys commands for the user to input
# his interface and new_mac address)
# dest= 'interface' and dest ='new_mac' are where the inputs from the user are linked to the change_mac() function.
# if the user input wrong interface and/or mac_address, parser.error() will return the intended print statements.
# together with subprocess.call imported function from the subprocess module, the 'interface' and 'new_mac' are
# linked and executed in the cmd in the background with the aid of subprocess module.
# finally, options = get_arguments() is to make options equal to get_argument() and so in the next line (line 37)
# We can throw options.interface and options.new_mac as parameters for change_mac() for the function to execute and
# change mac address


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change mac address, e.g eth0")
    parser.add_option("-m", "--mac", dest="new_mac", help="New mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Pls specify an interface, use --help for more help")
    elif not options.new_mac:
        parser.error("[-] Pls specify a new mac, use --help for more help")
    return options


def change_mac(interface, new_mac):
    print("[+] changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address!")


options = get_arguments()


current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[-] MAC address did not change.")

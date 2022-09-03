#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="IP address or IP range to scan")
    options = parser.parse_args()
    if not options.ip:
        parser.error("[-!] Please specify a valid IP address or CIDR range with the -i option")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("\tIP\t\t\t\tMAC Address ")
    print("[+]-----------------------NET WALK-----------------------------[+]\n")
    for client in results_list:
        print("\t" + client["ip"] + "\t\t\t" + client["mac"])
    print("------------------------------------------------------------------\n")


args = get_arguments()
scan_result = scan(args.ip)
print_result(scan_result)

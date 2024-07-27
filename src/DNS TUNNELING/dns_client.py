#cod inspirat din curs

from scapy.all import DNS, DNSQR
import socket
import base64

# Funcția care trimite o cerere DNS pentru un chunk specific al unui fișier
def send_dns_request(filename, chunk_number):
    dest = ('130.61.56.181', 53)  # Adresa IP și portul serverului DNS
    query_name = f"{filename}.{chunk_number}"  # Numele cererii DNS format din numele fișierului și numărul chunk-ului
    dns = DNS(rd=1, qd=DNSQR(qname=query_name, qtype="TXT", qclass=1))  # Creează o cerere DNS de tip TXT

    # Creează un socket UDP pentru a trimite cererea DNS
    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.sendto(bytes(dns), dest)  # Trimite cererea DNS la server
    simple_udp.settimeout(5)  # Setează un timeout de 5 secunde pentru a primi răspunsul

    answer, _ = simple_udp.recvfrom(65535)  # Așteaptă răspunsul de la server
    response = DNS(answer)  # Interpretează răspunsul ca un pachet DNS

    rdata = None
    if response.an and response.an.type == 16:  # Verifică dacă răspunsul conține un record TXT
        rdata = ''.join(rdata.decode() for rdata in response.an.rdata)  # Decodifică datele din recordul TXT

    return rdata  # Returnează datele decodificate

# Funcția principală care gestionează descărcarea fișierului
def avengers(filename):
    timeout = 5  # Numărul de încercări înainte de a renunța
    chunk_number = 0  # Indexul chunk-ului curent
    chunks = []  # Lista pentru a stoca toate chunk-urile primite

    while True:
        chunk = send_dns_request(filename, chunk_number)  # Trimite o cerere pentru chunk-ul curent
        if chunk:
            if chunk == "END":  # Verifică dacă este finalul fișierului
                break
            chunk = base64.b64decode(chunk)  # Decodifică chunk-ul din base64
            chunks.append(chunk)  # Adaugă chunk-ul la lista de chunk-uri
            chunk_number += 1  # Incrementează indexul chunk-ului
        else:
            if timeout == 0:  # Dacă timeout-ul este 0, renunță
                break
            else:
                timeout -= 1  # Decrementează timeout-ul și încearcă din nou
    
    final_data = b''.join(chunks)  # Concatenază toate chunk-urile pentru a forma fișierul final
    with open(filename, 'wb') as file:  # Deschide fișierul pentru scriere
        file.write(final_data)  # Scrie datele finale în fișier
    
# Numele fișierului pe care dorim să-l descărcăm
filename = "ciprian"
avengers(filename)  # Apelează funcția principală pentru a începe descărcarea fișierului

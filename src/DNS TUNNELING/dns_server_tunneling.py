#cod inspirat din curs

from scapy.all import DNS, DNSRR
import socket
import base64
import os

# Creare socket UDP și binding pe portul 53
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))

# Funcție pentru a citi fișierul în bucăți (chunk-uri) de mărime fixă
def read_file_in_chunks(file_path, chunk_size=255):
    with open(file_path, 'rb') as file:  # Deschide fișierul pentru citire în mod binar
        while True:
            chunk = file.read(chunk_size)  # Citește o bucată de dimensiune chunk_size
            if not chunk:  # Dacă nu mai sunt date de citit, ieși din buclă
                break
            yield chunk  # Returnează bucata citită

records = {
    "caini.live.": "130.61.56.181",
    "alexco.caini.live.": "130.61.56.181"
}

# Bucle pentru a asculta cererile DNS și a răspunde la acestea
while True:
    request, adresa_sursa = simple_udp.recvfrom(65535)  # Primește o cerere DNS
    packet = DNS(request)  # Interpretează cererea ca un pachet DNS
    dns = packet.getlayer(DNS)
    
    if dns is not None and dns.opcode == 0:  # Verificăm dacă este o cerere DNS (query)
        print("Got: ", packet.summary())
        query_name = dns.qd.qname.decode().strip(".")  # Extragem numele cererii DNS
        
        if query_name in records:  # Dacă cererea se referă la o înregistrare DNS existentă
            dns_answer = DNSRR(
                rrname=dns.qd.qname,
                ttl=330,
                type="A",
                rclass="IN",
                rdata=records[query_name]
            )
            dns_response = DNS(
                id=packet[DNS].id,
                qr=1,
                aa=1,
                rcode=0,
                qd=packet.qd,
                an=dns_answer
            )
        else:
            # Extragem numele fișierului și indexul chunk-ului din numele cererii
            parts = query_name.split(".")
            filename = parts[0]
            chunk_index = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            file_path = f"{filename}.txt"  # Calea fișierului pe server

            if os.path.exists(file_path):  # Dacă fișierul există pe server
                # Citim fișierul în bucăți și le codificăm în base64
                chunk_generator = read_file_in_chunks(file_path)
                chunks = [base64.b64encode(chunk).decode() for chunk in chunk_generator]

                if chunk_index < len(chunks):  # Dacă indexul chunk-ului este valid
                    chunk_encoded = chunks[chunk_index]
                    dns_answer = DNSRR(
                        rrname=dns.qd.qname,
                        ttl=330,
                        type="TXT",
                        rclass="IN",
                        rdata=chunk_encoded
                    )
                    dns_response = DNS(
                        id=packet[DNS].id,
                        qr=1,
                        aa=1,
                        rcode=0,
                        qd=packet.qd,
                        an=dns_answer
                    )
                else:  # Dacă am ajuns la finalul fișierului
                    dns_response = DNS(
                        id=packet[DNS].id,
                        qr=1,
                        aa=1,
                        rcode=0,
                        qd=packet.qd,
                        an=DNSRR(rrname=dns.qd.qname, ttl=330, type="TXT", rclass="IN", rdata="END")
                    )
            else:  # Dacă fișierul nu există pe server
                dns_response = DNS(
                    id=packet[DNS].id,
                    qr=1,
                    aa=1,
                    rcode=3,
                    qd=packet.qd
                )

        print('Response: ', dns_response.summary())
        simple_udp.sendto(bytes(dns_response), adresa_sursa)  # Trimite răspunsul DNS către client

simple_udp.close()

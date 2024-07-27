import socket
import traceback
import requests    
import json
import matplotlib.pyplot as plt
from mpl_toolkits.basemap import Basemap

from mdutils.mdutils import MdUtils

import requests

# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(3)

tabel_fisier = ["query", "status", "message", "country", "regionName", "city", "lat", "lon"]
locatii = []

def traceroute(ip, port, hop):
    # setam TTL in headerul de IP pentru socketul de UDP
    TTL = hop
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)

    # trimite un mesaj UDP catre un tuplu (IP, port)
    udp_send_sock.sendto(b'salut', (ip, port))

    # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
    # in cazul nostru nu verificăm tipul de mesaj ICMP
    # puteti verifica daca primul byte are valoarea Type == 11
    # https://tools.ietf.org/html/rfc792#page-5
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
    addr = '*'
    try:
        data, addr = icmp_recv_socket.recvfrom(63535)
    except Exception as e:
        print("Socket timeout ", str(e))
        # print(traceback.format_exc())
    print (f"{addr} TTL: <{TTL}>")
    return addr

'''
 Exercitiu hackney carriage (optional)!
    e posibil ca ipinfo sa raspunda cu status code 429 Too Many Requests
    cititi despre campul X-Forwarded-For din antetul HTTP
        https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    si setati-l o valoare in asa fel incat
    sa puteti trece peste sistemul care limiteaza numarul de cereri/zi

    Alternativ, puteti folosi ip-api (documentatie: https://ip-api.com/docs/api:json).
    Acesta permite trimiterea a 45 de query-uri de geolocare pe minut.
'''

def locatie(ip):
    fake_HTTP_header = {
                        'referer': 'http://ip-api.com',
                        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
                    }

    raspuns = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,query', headers=fake_HTTP_header)
    
    dict_raspuns = raspuns.json()

    return dict_raspuns


def adauga_locatie_tabel(loc):
    if loc["lat"] != "-":
        locatii.append((float(loc["lat"]), float(loc["lon"])))
    
    linie_tabel = [loc["query"]]
    linie_tabel.extend([loc[el] for el in loc][:-1])
    tabel_fisier.extend(linie_tabel)


def generare_harta(nume, adresa_host):
    plt.figure()
    harta = Basemap(projection="merc",llcrnrlat=-80,urcrnrlat=80,llcrnrlon=-180,urcrnrlon=180,resolution='l')
    harta.drawcoastlines()
    harta.drawcounties()
    harta.drawmapboundary(fill_color='aqua')
    harta.fillcontinents(color='lightgreen', lake_color='aqua')

    longitudini, latitudini = zip(*locatii)
    oX, oY = harta(latitudini,longitudini)
    harta.plot(oX, oY, marker='o', markerfacecolor='red',color='blue')

    plt.title(f"Traceroute for {nume}")
    adresa = adresa_host.replace(".","-")
    nume_site = nume.replace(".","-")
    plt.savefig(f"../traceroute_imgs/traceroute_{nume_site}_din_{adresa}.png")


def adaugare_in_fisier_markdown(nume, addr, public_ip):
    try:
        with open("../markdown.md", "r") as f:
            continut_existent = f.read()
    except:
        continut_existent = ""
    
    fisier_md = MdUtils(file_name='../markdown')
    fisier_md.new_paragraph(continut_existent)

    public_ip = public_ip.replace("-",".")
    # fisier_md.new_header(level=2, title=f"traceroute for {nume}({addr})")
    fisier_md.new_paragraph(f"## traceroute for {nume}({addr})")
    fisier_md.new_paragraph(f"host: {public_ip}")

    nume_site = nume.replace(".","-")
    public_ip = public_ip.replace(".","-")
    fisier_md.new_table(columns=8, rows=len(tabel_fisier)//8, text=tabel_fisier)
    fisier_md.new_paragraph(fisier_md.new_inline_image(text=f"harta_{nume}", path=f"/traceroute_imgs/traceroute_{nume_site}_din_{public_ip}.png"))
    fisier_md.create_md_file()



def main():
    hop = 1
    MAX_TTL = 30
    nume = 'www.cbn.co.za'
    addr = socket.gethostbyname(nume)

    raspuns = requests.get('https://api.ipify.org?format=json')
    public_ip = raspuns.json()['ip']

    public_ip = public_ip.replace(".","-")

    print(f"traceroute for {nume}({addr})")

    while True:
        addr_from_trace_route = traceroute(addr, 33434, hop)

        loc = {
            "status": "-",
            "message": "-",
            "country": "-",
            "regionName": "-",
            "city": "-",
            "lat": "-",
            "lon": "-",
            "query": addr_from_trace_route[0]}
        
        if addr_from_trace_route[0] != '*':
            result = locatie(addr_from_trace_route[0])
            for col in result:
                loc[col] = result[col]
        
        adauga_locatie_tabel(loc)

        if addr == addr_from_trace_route[0] or hop == MAX_TTL:
            break
        hop += 1

    generare_harta(nume, public_ip)

    adaugare_in_fisier_markdown(nume, addr, public_ip)


if __name__ == '__main__':
    main()

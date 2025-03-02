import sys
import sqlite3
import socket
import os

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e

DB_NAME = "CACHEDB.db"
PATH_OF_DB = "SQL"
FULL_PATH = f"{PATH_OF_DB}/{DB_NAME}"
ADDRESS = ("0.0.0.0", 53)


def handle_dns_request(data, address, server_socket):
    packet = IP(data)
    dns_packet = packet[UDP].payload

    dns_response = DNS(
        id=dns_packet.id,
        qr=1,
        opcode=0,
        aa=1,
        tc=0,
        rd=0,
        ra=0,
        rcode=0,
        qd=dns_packet.qd,
        an=DNSRR(
            rrname=dns_packet.qd.qname,
            ttl=60,
            rdata="1.2.3.4"
        ),
    )

    ip_response = IP(src=packet[IP].dst, dst=packet[IP].src)
    udp_response = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
    response_packet = ip_response / udp_response / dns_response

    server_socket.sendto(bytes(response_packet), address)


def main():
    if not os.path.exists(PATH_OF_DB):
        os.makedirs(PATH_OF_DB)

    conn = sqlite3.connect(FULL_PATH)
    cursor = conn.cursor()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(ADDRESS)

    while True:
        data, address = server_socket.recvfrom(1024)
        handle_dns_request(data, address, server_socket)

    conn.close()


if __name__ == "__main__":
    main()

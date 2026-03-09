from scapy.all import ARP, Ether, srp
import socket
import argparse
import netifaces
import netaddr
import ipaddress
import os
import struct

parse = argparse.ArgumentParser()
parse.add_argument('-i', '--interface', help='Interfaces para escanear (eth0, en0, lo, wlo1...)', 
                    type=str, required=True)

args = parse.parse_args()

def get_local(interface):
    try:
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print(e)

    netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']

    range = netaddr.IPAddress(netmask).netmask_bits()
    
    return f'{ip}/{range}'

def checksum_calc(data):
    checksum = 0

    if len(data) % 2 != 0:
        data += b"\x00"
    for i in range(0, len(data), 2): 
        word = (data[i] << 8) + data[i+1]
        checksum += word

    checksum = (checksum >>16) + (checksum & 0xFFFF)
    checksum += checksum >> 16 

    return ~checksum & 0xFFFF 

def net_scanner(ip, interface):
    print("CTRL-C para encerrar")
    f = open("hosts.txt", "w", encoding="utf-8")
    f.write("[*] Hosts [*]")

    request = ARP(pdst = ip)
    frame = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = frame / request
    res = srp(packet, timeout=2, retry=1, 
              iface=interface, verbose=0)[0]
    print("[!] ARP [!]")
    f.write("\n\n[!] Detectados com ARP [!]")
    for sent, received in res:
        if received:
            print(f'{received.psrc} - {received.hwsrc}')
            f.write(f'\n[*] IP: {received.psrc} MAC: {received.hwsrc} [*]')
    
    print("[!] ICMP [!]")
    f.write("\n\n[!] Detectados com ICMP [!]")

    net = ipaddress.ip_network(ip, strict=False)
    if os.name == 'posix':
        request_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    else:
        request_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP, socket.IP_HDRINCL)
    
    request_sock.settimeout(2)
    
    for ip in net.hosts():

        type = 8 
        code = 0 
        checksum = 0
        id = os.getpid() & 0xFFFF
        sequence = 1
        payload = b'abcd'

        header = struct.pack("!BBHHH", type, code, checksum, id, sequence)
        packet = header + payload

        checksum = checksum_calc(packet)
        header = struct.pack("!BBHHH", type, code, checksum, id, sequence)

        try:
            request_sock.sendto(packet, (str(ip), 0))
            response, addr = request_sock.recvfrom(1024)

            ihl = (response[0] & 0x0F) * 4
            icmp_offset = ihl
            icmp_type = response[icmp_offset]
            icmp_code = response[icmp_offset + 1]
            icmp_id = (response[icmp_offset + 4] << 8) + response[icmp_offset + 5]

            if icmp_type == 0 and icmp_code == 0 and icmp_id == id:
                print(f'{addr[0]}, {response[icmp_offset]}')
                f.write(f"\nIP: {addr[0]}")
        except socket.timeout:
            pass
        
    request_sock.close()

if __name__ == '__main__':
    net = get_local(args.interface)
    net_scanner(net, args.interface)

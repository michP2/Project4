#The code run without any errors on Pycharm, Kali Operating System
import socket
import struct
import textwrap

def main():
    #creating a connection with the network
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #loop listening and waiting to capture data
    while True:
        raw_data, addr= connection.receivefrom(65536)
        dest_mac, src_mac, ethernet_proto, data= ethernet_frame(raw_data)
        print('Ethenet Frame')
        print('Destination Mac-Address {}, Source_Mac-Address {}, Protocol {}'.format (dest_mac, src_mac,ethernet_proto))

        if ethernet_proto == 8:
            (version, header_length, ttl, proto, source, target, data) = ipv4_packet(data)
            print('IPv4 Packet')
            print('Version: {}, Header Length: {}, TTL: {}, Protocol: {}'.format(version, header_length, ttl, proto))
            print('Source: {}, Target: {}'.format(source, target))

        # Checking the number of protocol
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print('ICMP Packet: ')
            print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
            print('Data:')
            print(data)

        elif proto == 6:
            (source_port, destiantion_port, sequence, acknowledgement, flag_ugh, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin, data[offset:]) = tcp_section(data)
            print('TCP Section')
            print('Soiurce Port: {], Destination Port:{}, Sequence: {}'.format(source_port, destiantion_port, sequence))
            print('Acknowledgement: {}'.format(acknowledgement))
            print('Data:')
            print(data)

        elif proto == 17:
            source_port, destiantion_port, size, data = udp_section(data)
            print('UDP Section')
            print('Source Port: {},Destiantion Port: {}, Size: {}')
            print('Data')
            print(data)


#Unpacking ethernet frame captured
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!: 6s 6s H', data[:14])
    return get_macAddress(dest_mac), get_macAddress(src_mac), socket.htons(proto), data[14:]


#formating the mac-address to human readable data ie AA:BB:CC:DD:EE:FF
def get_macAddress(addr):
    addr_str = map('{:02x}'.format, addr)
    macAddress =':'.join(addr_str.upper())
    return macAddress

#Unpacking the IPv4 Packet
def ipv4_packet(data):
    version_header_length=data[0]
    version = version_header_length >> 4
    header_length =(version_header_length & 15) *4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#format ipv4 address ie 192.168.2.1
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpack the  icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack if the data is TCP
def tcp_section(data):
    (source_port, destiantion_port, sequence, acknowledgement, offset_reserved_flags)=struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_ugh = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin =  offset_reserved_flags & 1
    return source_port,destiantion_port, sequence, acknowledgement, flag_ugh,flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack if the data is UDP
def udp_section(data):
    source_port, destiantion_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destiantion_port, size, data[8:]


main()

#The code, on running, gave an error AttributeError: module 'socket' has no attribute 'AF_PACKET'
import socket
import struct
import textwrap

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr= connection.receivefrom(65536)
        dest_mac, src_mac, ethernet_proto, data= ethernet_frame(raw_data)
        print('Ethenet Frame')
        print('Destination Mac-Address {}, Source_Mac-Address {}, Protocol {}'.format (dest_mac, src_mac,ethernet_proto))

#Unpacking ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!: 6s 6s H', data[:14])
    return get_macAddress(dest_mac), get_macAddress(src_mac), socket.htons(proto), data[14:]


#formating the mac-address
def get_macAddress(addr):
    addr_str = map('{:02x}'.format, addr)
    macAddress =':'.join(addr_str.upper())
    return macAddress


main()
print("Credit to youtube video by thenewboston Packet Network Sniffer Tutorial")
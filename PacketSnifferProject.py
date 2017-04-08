#This code produced an OSError: [WinError 10043] protocol is not configured into this system
import socket
import struct
import textwrap

def main():
    conn= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr= conn .receivefrom(65536)
        dest_mac, src_mac, ethernet_proto, data=frame(raw_data)
        print('Ethenet Frame')
        print('Destination Mac-Address {}, Source_Mac-Address {}, Protocol {}'.format (dest_mac, src_mac, ethernet_proto))

#To unpack the ethernet frame


def frame(data):
    dest_mac, src_mac, type =struct.unpack('! 6s 6s H',data[:14])
    return get_destmacAddress(dest_mac), get_srcAddress(src_mac),socket.hton(type), data[14:]


#formating the mac-address
def get_macAddress(addr):
    addr_str = map('{:02x}'.format, addr)
    macAddress =':'.join(addr_str.upper())
    return macAddress

print("Credit to youtube videos by the thenewboston: Packet Network Sniffer Tutorials")
main()
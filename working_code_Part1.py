#The code run without any errors on Pycharm Kali Operating System
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

#Unpacking ethernet frame captured
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!: 6s 6s H', data[:14])
    return get_macAddress(dest_mac), get_macAddress(src_mac), socket.htons(proto), data[14:]


#formating the mac-address to human readable data ie AA:BB:CC:DD:EE:FF
def get_macAddress(addr):
    addr_str = map('{:02x}'.format, addr)
    macAddress =':'.join(addr_str.upper())
    return macAddress


main()

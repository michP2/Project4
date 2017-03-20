import socket
import struct
import textwrap

#To unpack the ethernet frame

def frame(data):
    des_mac, src_mac, type =struct.unpack('! 6s 6s H',data[:14])
    return get_macAddress(des_mac), get_srcAddress(src_mac),socket.hton(type), data[14:]


#formating the mac-address
def get_macAddress(addr):
    addr_str = map('{:02x}'.format, addr)
    macAddress =':'.join(addr_str.upper())
    return macAddress

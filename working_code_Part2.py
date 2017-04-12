#Unpacking the IPv4 Packet
def ipv4_packet(data):
    version_header_length=data[0]
    version = version_header_length >> 4
    header_length =(version_header_length & 15) *4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])# struct  is underlined because this part of the code is going to be part of the main function in Part 1 where import is sruct is used
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#format ipv4 address ie 192.168.2.1
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpack the  icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
#Unpack TCP section
def tcp_section(data):
    (source_port, destiantion_port, sequence, acknowledgement, offset_reserved_flags)=struct.unpack('! H H L L H',data[:14])
    offset= (offset_reserved_flags >> 12) * 4
    flag_ugh = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin =  offset_reserved_flags & 1
    return source_port,destiantion_port, sequence, acknowledgement, flag_ugh,flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_section(data):
    source_port, destiantion_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destiantion_port, size, data[8:]







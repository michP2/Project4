#This code will be just after the while loop in working_code_Part1.py
#checking what protocol number is in the data

if ethernet_proto == 8:
    (version, header_length, ttl, proto, source, target, data)= ipv4_packet(data)
    print('IPv4 Packet')
    print('Version: {}, Header Length: {}, TTL: {}, Protocol: {}'.format(version, header_length, ttl, protocol))
    print('Source: {}, Target: {}'.format(source, target))

    #Checking the number of protocol
    if proto == 1:
        icmp_type, code checksum data = icmp_packet(data)
        print('ICMP Packet: ')
        print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type,code, checksum))
        print('Data:')
        print(data)
#
    elif proto == 6:
        (source_port,destiantion_port, sequence, acknowledgement, flag_ugh,flag_ack,flag_psh, flag_rst, flag_syn, flag_fin,data[offset:])= tcp_section(data)
        print('TCP Section')
        print('Soiurce Port: {], Destination Port:{}, Sequence: {}'.format(source_port,destiantion_port,sequence))
        print('Acknowledgement: {}'.format(acknowledgement))
        print('Data:')
        print(data)

    elif proto == 17:
        source_port, destiantion_port, size, data = udp_section(data)
        print('UDP Section')
        print('Source Port: {},Destiantion Port: {}, Size: {}')
        print('Data')
        print(data)


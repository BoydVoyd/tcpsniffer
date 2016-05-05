#!/home/hiro/Projects/pfp/bin/python2.7

import socket
import netframes

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))

while 1:
    raw_frame = rawSocket.recvfrom(65535)
    try:
        frame = netframes.EthFrame(raw_frame[0])
    except ValueError, ex:
    #    print str(ex)
        continue
    frame.print_all_fields()
    frame.print_data()

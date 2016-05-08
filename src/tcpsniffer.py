#!/home/hiro/Projects/tcpsniff/bin/python3.5
import psycopg2
import socket
import netframes

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
try:
    conn=psycopg2.connect("dbname='pfpsite' user='hiro' password='$nowCrash'")
except psycopg2.Error as e:
    print("I am unable to connect to the database.")
    print(e.pgerror)
cur = conn.cursor()

while 1:
    raw_frame = rawSocket.recvfrom(65535)
    try:
        frame = netframes.EthFrame(raw_frame[0])
    except ValueError as ex:
        print(str(ex))
        continue
    frame.print_all_fields()
    frame.print_data()

#!/home/hiro/Projects/tcpsniff/bin/python3.5
import psycopg2
import socket
import netframes

#rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
#                          socket.htons(0x0003))
try:
    conn=psycopg2.connect("dbname='pfpsite' user='hiro' password='$n0wCrash'")
except psycopg2.Error as e:
    print("I am unable to connect to the database.")
    print(e.pgerror)
cur = conn.cursor()

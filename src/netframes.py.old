import socket
import struct
import binascii
import sys
import datetime

class EthFrame:
    def __init__(self, frame):
        self.frame = frame
        self.ETH_HDR_LEN= 14
        self.TCP_IP_HDR_BASE_LEN= 20
        self.fields = {}
        self.headers = {}
        self.dt = datetime.datetime.now()
        self.eth_hdr_str = self.frame[0:self.ETH_HDR_LEN]
        self.headers["ethernet"] = struct.unpack("!6s6s2s", self.eth_hdr_str)
        self.fields["time"] = self.dt.time()
        self.fields["date"] = self.dt.date()
        self.fields["src_mac"] = binascii.hexlify(self.headers["ethernet"][0])
        self.fields["dst_mac"] = binascii.hexlify(self.headers["ethernet"][1])
        self.fields["eth_type"] = binascii.hexlify(self.headers["ethernet"][2])
        if self.fields["eth_type"] != "0800":
            raise ValueError("IP Only!")
        else:
            self.ip_hdr_str = self.frame[self.ETH_HDR_LEN: \
                self.ETH_HDR_LEN + self.TCP_IP_HDR_BASE_LEN]
            self.headers["ip"] = struct.unpack("!BBHHHBBH4s4s", self.ip_hdr_str)
            self.fields["ip_ver"] = self.headers["ip"][0] >> 4
            self.fields["ip_hdr_len_words"] = self.headers["ip"][0] & 0xF
            self.fields["ip_hdr_len_bytes"] =  \
                self.fields["ip_hdr_len_words"] * 4
            self.fields["ip_dscp"] = self.headers["ip"][1] >> 2
            self.fields["ip_ecn"] = self.headers["ip"][1] & 0x3
            self.fields["ip_total_len"] = self.headers["ip"][2]
            self.fields["ip_id"] = self.headers["ip"][3]
            self.fields["ip_df_set"] = self.get_bit(self.headers["ip"][4], 14)
            self.fields["ip_mf_set"] = self.get_bit(self.headers["ip"][4], 13)
            self.fields["ip_offset"] = self.headers["ip"][4] & 0x102B36211C7
            self.fields["ip_ttl"] = self.headers["ip"][5]
            self.fields["ip_proto"] = self.headers["ip"][6]
            if self.fields["ip_proto"] != 6:
                raise ValueError("TCP Only!")
            else:
                self.fields["ip_checksum"] = self.headers["ip"][7]
                self.fields["ip_src_addr"] = \
                    socket.inet_ntoa(self.headers["ip"][8])
                self.fields["ip_dst_addr"] = \
                    socket.inet_ntoa(self.headers["ip"][9])
                self.fields["eth_ip_hdr_len"] = self.ETH_HDR_LEN+ \
                    self.fields["ip_hdr_len_bytes"]
                self.tcp_hdr_str = self.frame[self.fields["eth_ip_hdr_len"]: \
                    self.fields["eth_ip_hdr_len"] + self.TCP_IP_HDR_BASE_LEN]
                self.headers["tcp"] = \
                    struct.unpack("!HHLLBBHHH", self.tcp_hdr_str)
                self.fields["tcp_src_port"] = self.headers["tcp"][0]
                self.fields["tcp_dst_port"] = self.headers["tcp"][1]
                self.fields["tcp_seq"] = self.headers["tcp"][2]
                self.fields["tcp_ack"] = self.headers["tcp"][3]
                self.fields["tcp_off_res"] = self.headers["tcp"][4]
                self.fields["tcp_hdr_len"] = \
                    (self.fields["tcp_off_res"] >> 4) * 4
                self.fields["all_hdr_len"] = \
                    self.fields["eth_ip_hdr_len"] + self.fields["tcp_hdr_len"]
                self.fields["data"] = self.frame[self.fields["all_hdr_len"]:]

    def print_eth_fields(self):
        print "Eth Info:"
        print "Src MAC: " + self.fields["src_mac"] + " | Dst MAC : " + \
              self.fields["dst_mac"] + " | Eth type: " + \
              self.fields["eth_type"] + " | Date: " + str(self.fields["date"])+\
              " | Time: " + str(self.fields["time"])+\
              "\n"

    def print_ip_fields(self):
        print "IP Info:"
        print "IP Ver: " + str(self.fields["ip_ver"]) + \
              " | IP Hdr (Bytes): " + str(self.fields["ip_hdr_len_bytes"]) + \
              " | DSCP: " + str(self.fields["ip_dscp"]) + \
              " | ECN: " + str(self.fields["ip_ecn"]) + \
              " | Pkt (Bytes): " + str(self.fields["ip_total_len"])
        print "ID: " + str(self.fields["ip_id"]) + \
              " | DF Flag: " + str(self.fields["ip_df_set"]) + \
              " | MF Flag: " + str(self.fields["ip_mf_set"]) + \
              " | Offset: " + str(self.fields["ip_offset"]) + \
              " | Time to Live: " + str(self.fields["ip_ttl"])
        print "Protocol: " + str(self.fields["ip_proto"]) + \
              " | Hdr Cheksum: " + str(self.fields["ip_checksum"]) + \
              " | Src IP: " + self.fields["ip_src_addr"] + \
              " | Dst IP: " + self.fields["ip_dst_addr"] + "\n"

    def print_tcp_fields(self):
        print "TCP Info:"
        print "Src Port: " + str(self.fields["tcp_src_port"]) + \
              " | Dst Port: " + str(self.fields["tcp_dst_port"]) + \
              " | Seq Num: " + str(self.fields["tcp_seq"]) + \
              " | ACK: " + str(self.fields["tcp_ack"])
        print "TCP Hdr Len (Bytes): " + str(self.fields["tcp_hdr_len"]) + "\n"

    def print_all_fields(self):
        self.print_eth_fields()
        self.print_ip_fields()
        self.print_tcp_fields()
        print "----------------------------------------" + \
              "----------------------------------------" + "\n"

    def print_data(self):
        if self.fields["data"].rstrip() != "":
            #print "Data: "
            print self.fields["data"]
            #print "----------------------------------------" + \
            #      "----------------------------------------" + "\n"

    def get_bit(self, byteval, pos):
        return (byteval & (1 << pos)) != 0

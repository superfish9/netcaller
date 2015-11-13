#coding=utf-8

import socket
import sys
import random
import struct


# 计算校验和
def checkSum(msg):
    s = 0
    
    # 每次取16位
    for i in range(0, len(msg), 2):
        w = (ord(msg[i])<<8) + (ord(msg[i+1]))
        s += w
    
    s = (s>>16) + (s & 0xffff)
    s = ~s & 0xffff
    
    return s

# 创建原始套接字
def createSocket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except socket.error, msg:
        print 'Create socket error :', str(msg[0]), 'message :', msg[1]
        sys.exit()
    
    # 设置手工提供IP头
    s.setsockopt(socket.IPPROTO_TCP, socket.IP_HDRINCL, 1)  
    
    return s

# 创建IP头
def createIPHeader(source_ip, dest_ip):
    
    # IP头字段
    headerlen = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    iid = random.randrange(18000, 65535, 1)
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10
    saddr = socket.inet_aton(source_ip)
    daddr = socket.inet_aton(dest_ip)
    hl_version = (version<<4) + headerlen
    ip_header = struct.pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, iid, frag_off, ttl, protocol, check, saddr, daddr)
        
    return ip_header

# 创建TCP头部
def createTCPHeader(source_ip, dest_ip, dest_port):
    
    # TCP头字段
    source_port = random.randrange(32000, 62000, 1)
    seq = 0
    ack_seq = 0
    doff = 5
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons(8192)
    check = 0
    urg_ptr = 0
    offset_res = (doff<<4) + 0
    tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5)
    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
    
    # 伪头部字段
    source_addr = socket.inet_aton(source_ip)
    dest_addr = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', source_addr, dest_addr, placeholder, protocol, tcp_length)
    psh += tcp_header
    
    # 计算校验和
    tcp_checksum = checkSum(psh)
    
    # 重新打包TCP头部，填入正确的校验和
    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
    
    return tcp_header

# SYN半开放扫描
def synScan(source_ip, dest_ip, start_port, end_port):
    
    # 开放的端口列表
    #syn_ack_received = []
    
    for dest_port in range(start_port, end_port):
        
    
        ip_header = createIPHeader(source_ip, dest_ip)
        tcp_header = createTCPHeader(source_ip, dest_ip, dest_port)
        
        packet = ip_header + tcp_header
        
        s = createSocket()
        s.sendto(packet, (dest_ip, 0))
        
        data = s.recvfrom(1024)[0][0:]
        
        ip_header_len = (ord(data[0]) & 0x0f) * 4
        tcp_header_len = ((ord(data[ip_header_len+12]) & 0xf0)>>4) * 4
        tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len]
        
        # 判断是否为syn/ack
        if ord(tcp_header_ret[13] == 0x12):
            #syn_ack_received.append(dest_port)
            print '[*] Host %s TCP port : %d' % (dest_ip, dest_port)
    
    return syn_ack_received

def main():
    source_ip = '10.206.11.241'
    dest_ip = '10.206.11.234'
    start_port = 50
    end_port = 500
      
    #port_list = []
    synScan(source_ip, dest_ip, start_port, end_port)
    
    return

if __name__ == "__main__":
    main()
    
    
        
        
        
        
        
        
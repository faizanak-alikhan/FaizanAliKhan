#!/usr/bin/env python3.7
import socket
import struct
import textwrap

TAB_1= '\t - '
TAB_2= '\t\t - '
TAB_3= '\t\t\t - '
TAB_4= '\t\t\t\t - '

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'

def main():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))


    while True:
        rawData,addr=conn.recvfrom(65536)
        destMac,srcMac,ethProto,data = ethernetFrame(rawData)
        print('\n ethernetFrame:')
        print(TAB_1 + 'Destination: {},Source: {},Protocol:{}'.format(destMac,srcMac,ethProto))
        

        if ethProto==8:
            version,headerLen,ttl,proto,src,target,data = ipv4Packet(data)
            print (TAB_1 + 'IPV4 Packet')
            print (TAB_2 + 'Version {},Header Lenth {},TTL {},Protocol {}, Source{}, Target{}'.format(version,headerLen,ttl,proto,src,target))

            if proto == 6:
                srcPort,destPort,sequence,ack,flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin,data=tcpSeg(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(srcPort,destPort))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence,ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flagUrg,flagAck,flagPsh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flagRst,flagSyn,flagFin))

                
            # UDP
            elif proto == 17:
                code,idt,lent,auth,data = udpSeg(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(srcPort,destPort,size))
                srcPort,destPort,size,data = RadiusSeg(data)
                print(TAB_1 + 'RADIUS Segment:')
                print(TAB_2 + 'Code: {}, Identity: {}, Length: {}, Authentication: {}'.format(code,idt,lent,auth))

        else:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2,data))

        



#unpack ethernetframe
def ethernetFrame(data):
    destMac,srcMac,ethProto= struct.unpack('!6s 6s H',data[:14])
    return getMacAddr(destMac),getMacAddr(srcMac),socket.htons(ethProto),data[:14]

#format mac address
def getMacAddr(bytesAddr):
    bytesStr = map('{:02x}'.format,bytesAddr)
    return ':'.join(bytesStr).upper()

#inpack ipv4
def ipv4Packet(data):
    versionHeaderLen = data[0]
    version = versionHeaderLen >>4
    headerLen = (versionHeaderLen & 15) * 4
    ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,headerLen,ttl,proto,ipv4(src),ipv4(target),data[headerLen:]

#format address ipv4
def ipv4(addr):
    return '.'.join(map(str,addr))

#TCP
def tcpSegm(data):
    (srcPort,destPort,sequence,ack,offsetFlags) = struct.unpack('! H H L L H',data[:14])
    offset = (offsetFlags) >> 12 *4
    flagUrg= (offsetFlags & 32) >> 5
    flagAck= (offsetFlags & 16) >> 4
    flagPsh= (offsetFlags & 8) >> 3
    flagRst = (offsetFlags & 4) >> 2
    flagSyn= (offsetFlags & 2) >> 1 
    flagFin= offsetFlags >> 1
    return srcPort,destPort,sequence,ack,flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin,data[offset:]

#UDP
def udpSeg(data):
    srcPort,destPort,size = struct.unpack('! H H 2x H',data[:8])
    return srcPort,destPort,size,data[8:]

#RADIUS
def RadiusSeg(data):
    code,idt,lent,auth = struct.unpack('! B B H 16s',data[:20])
    return code,idt,lent,auth,data[20:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    

main()

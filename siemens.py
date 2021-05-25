#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from struct import pack
import time
from scapy.all import *
from scapy.packet import Raw
from scapy.fields import ByteField, ShortField
from scapy.packet import Packet
import socket

COTP_START = b'\x11\xe0\x00\x00\x00\x14\x00\xc1\x02\x01\x00\xc2\x02\x00\xc0\x01\x0a'
COTP_PACKET = b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x05\x00\xc1\x02\x01\x00\xc2\x02\x02\x00\xc0\x01\x0a'
ROSCTR_SETUP = b'\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0'
READ_SZL =          b'\x03\x00\x00\x21\x02\xf0\x80\x32\x07\x00\x00\x00\x00\x00\x08\x00\x08\x00\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x11\x00\x01'
FIRST_SZL_REQ =     b'\x03\x00\x00\x21\x02\xf0\x80\x32\x07\x00\x00\x00\x00\x00\x08\x00\x08\x00\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x11\x00\x01'
SECOND_SZL_REQ =    b'\x03\x00\x00\x21\x02\xf0\x80\x32\x07\x00\x00\x00\x00\x00\x08\x00\x08\x00\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x1c\x00\x01'

MODULE_OFFSET = 43
HARDWARE_OFFSET = 71 
VERSION_OFFSET = 122
SYSTEM_NAME_OFFSET = 43
MODULE_TYPE_OFFSET = 77
SERIAL_NUM_OFFSET = 179
PLANT_ID_OFFSET = 111
COPYRIGHT_OFFSET = 145

RECV_SIZE = 1024 * 8

class TPKT(Packet):
    name = "TPKT"
    fields_desc = [ByteField("version", 3),
                   ByteField("reserved", 0),
                   ShortField("length", 0x0016)]

def connect_to_s7(ip, port):
    target = (ip, port)
    try:
        # TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(target)

        # COTP packet
        cotp_packet = Raw(load=COTP_PACKET)
        sock.send(bytes(cotp_packet))
        cotp_resp = sock.recv(RECV_SIZE)
        print(cotp_resp)

        # Setting up S7 comms
        rosctr_setup = Raw(load=ROSCTR_SETUP)
        sock.send(bytes(rosctr_setup))
        rosctr_setup_resp = sock.recv(RECV_SIZE)
        print(rosctr_setup_resp)

        # S7 ROSCTR: SZL read request
        szl_req = Raw(load=FIRST_SZL_REQ)
        sock.send(bytes(szl_req))
        szl_resp = sock.recv(RECV_SIZE)
        hexdump(szl_resp)
        parse_siemens_first_info_from_response(szl_resp)

        # S7 ROSCTR: second SZL read request
        second_szl_req = Raw(load=SECOND_SZL_REQ)
        sock.send(bytes(second_szl_req))
        second_szl_resp = sock.recv(RECV_SIZE)
        hexdump(second_szl_resp)
        parse_siemens_second_info_from_response(second_szl_resp)

    except Exception as error:
        logging.error(f'Error occurred: {error}')
    finally:
        sock.close()

def parse_siemens_first_info_from_response(response):
    p = Raw(response)

    # Module -> from [43] to a 0x00 -> String
    module = get_string(p, MODULE_OFFSET)
    print(f'Module: {module}')
    # Basic Hardware -> from [76] to a 0x00 -> String
    basic_hardware = get_string(p, HARDWARE_OFFSET)
    print(f'Basic Hardware: {basic_hardware}')
    # Version -> from [122] -> 3Bytes and concat with .
    firmware_version = get_bytes(p, VERSION_OFFSET, num_bytes=3)
    print(f'Version: {firmware_version}')

def parse_siemens_second_info_from_response(response):
    p = Raw(response)

    # System Name > from [43] to a 0x00 -> String
    sysname = get_string(p, SYSTEM_NAME_OFFSET)
    print(f'System Name: {sysname}')
    # Module Type > from [77] to a 0x00 -> String 
    module_type = get_string(p, MODULE_TYPE_OFFSET)
    print(f'Module Type: {module_type}')
    # Serial Number > from [179] to a 0x00 -> String 
    serial_num = get_string(p, SERIAL_NUM_OFFSET)
    print(f'Serial Number: {serial_num}')
    # Plant Identification > from [111] to a 0x00 -> String 
    plant_id = get_string(p, PLANT_ID_OFFSET)
    print(f'Plant Identification: {plant_id}')
    # Copyright > from [145] to a 0x00 -> String 
    copyr = get_string(p, COPYRIGHT_OFFSET)
    print(f'Copyright: {copyr}')

def get_string(packet, offset):
    cont = 0
    for b in packet.load[offset:]:
        if hex(b) != '0x0':
            cont +=1
        else:
            break
    str = packet.load[offset:offset+cont]
    str = str.decode('UTF-8')
    return str.strip()
    

def get_bytes(packet, offset, num_bytes=1):
    version = ''
    for x in range(offset, offset+num_bytes):
        if (hex(packet.load[x])) != '0x0':
            version += str(packet.load[x])+'.'

    return version[:-1]

if __name__ == '__main__':
    if len(sys.argv) <=2:
        logging.error("USAGE: <host> <port>")
        exit(1)
    
    connect_to_s7(sys.argv[1], int(sys.argv[2]))

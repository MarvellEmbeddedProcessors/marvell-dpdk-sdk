#!/usr/bin/env python3
# Copyright (C) 2022 Marvell.
# SPDX-License-Identifier: BSD-3-Clause

from scapy.all import *
import argparse

spi = 0x10000000
dmac = '13:13:13:13:13:13'

# Process command line args
parser = argparse.ArgumentParser()
parser.add_argument("--spi", type=str, help="SPI of ESP packet",
		    default=None)
parser.add_argument("--dmac", type=str, help="DMAC of pkts",
		    default=dmac)

args = parser.parse_args()
if args.spi != None:
	spi = int(args.spi, 16)

key = b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xca\xfe\xba\xbe'
eth = Ether(src='12:12:12:12:12:12', dst=dmac)

pkt = []
ep = []
tun=IP(src='192.168.1.2', dst='192.168.1.1')

sa=SecurityAssociation(proto=ESP, spi=spi, crypt_algo='AES-GCM',
                       crypt_key=key, tunnel_header=tun)

ip=IP(src='11.11.11.1', dst='11.11.11.2')

p=ip/TCP()/Raw(5 * 'a')

pkt.append(eth/p)
ep.append(eth/sa.encrypt(p))

pcap_name = 'inbound_%08x.pcap' % spi
wrpcap(pcap_name, ep)

sys.stdout.write("Generated %s with SPI %08x\n" % (pcap_name, spi))

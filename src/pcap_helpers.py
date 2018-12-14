#!/usr/bin/env python

# Helps read and process packet capture files (PCAPs)

import collections
import socket

from globals import FIELDS
from scapy.all import *

def read_pcap(filename):
	return rdpcap(filename)

def parse_pcap(filename):
	results = []
	data = read_pcap(filename)
	if not data:
		return results

	NetworkItem = collections.namedtuple('NetworkItem', ' '.join(FIELDS))
	for pkt in data:
		try:
			src_hw = pkt.src
			dst_hw = pkt.dst

			fin = 0
            ack = 0
            syn = 0
			rst = 0

			ip = pkt.haslayer('IP')
			ipv6 = pkt.haslayer('IPv6')
			if ip or ipv6:
				if ip:
					src_ip = pkt['IP'].src
					dst_ip = pkt['IP'].dst
				elif ipv6:
					src_ip = pkt['IPv6'].src
					dst_ip = pkt['IPv6'].dst

				try:
					if pkt['IP'].proto == 1:
						protocol = 'icmp'
					if pkt['IP'].proto == 2:
						protocol = 'igmp'
				except:
					pass

				try:
					if pkt['IPv6'].nh == 58:
						protocol = 'icmpv6'
				except:
					pass

				if pkt.haslayer('TCP'):
					src_port = pkt.sport
					dst_port = pkt.dport

					FIN = 0x01
					SYN = 0x02
					RST = 0x04
					ACK = 0x10

					fin = pkt['TCP'].flags & FIN
					ack = pkt['TCP'].flags & ACK
					rst = pkt['TCP'].flags & RST
					syn = pkt['TCP'].flags & SYN
				elif pkt.haslayer('UDP'):
					src_port = pkt.sport
					dst_port = pkt.dport
			elif pkt.haslayer('EAPOL'):
				protocol = 'eapol'
			elif pkt.haslayer('LLC'):
				src_port = pkt.ssap
				dst_port = pkt.dsap
				protocol = 'llc'
			elif pkt.haslayer('ARP'):
				protocol = 'arp'

			if src_port and dst_port:
				protocol = get_protocol(src_port, dst_port)
			elif not protocol:
				protocol = ' '.join(enumerate_layers(pkt))
			else:
				protocol = 'unknown'#TODO

			try:
				ip_bytes = len(pkt[IP].payload)
			except:
				ip_bytes = 0

			# TODO: add syn, ack, window_size info
			ni = NetworkItem(
				ts = float(pkt.ts),\
				uid = None,\
				orig_m = src_mac,\
				orig_h = src_ip,\
				orig_p = src_port,\
				resp_m = dst_mac,\
				resp_h = dst_ip,\
				resp_p = dst_port,\
				proto = protocol,\
				service = None,\
				duration = 0,\
				orig_bytes = len(size),\
				resp_bytes = None,\
				conn_state = (syn,ack,rst,fin),\
				local_orig = None,\
				local_resp = None,\
				missed_bytes = 0,\
				history = None,\
				orig_pkts = 1,\
				orig_ip_bytes = ip_bytes,\
				resp_pkys = None,\
				resp_ip_bytes = None,\
				tunnel_parents = None,\
				type = 'packet',
			)
			results.append(ni)
		except Exception as e:
			print 'Error parsing pcap', repr(e)

	return pkts

	def get_protocol(self, src_port, dst_port):
        # get protocol based on dst_port
        try:
            return socket.getservbyport(dst_port)
        except socket.error:
            pass
        # get protocol based on src_port (if not, unknown)
        try:
            return socket.getservbyport(src_port)
        except socket.error:
            return 'unknown ({0}->{1})'.format(src_port, dst_port)

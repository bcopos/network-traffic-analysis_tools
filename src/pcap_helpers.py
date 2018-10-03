#!/usr/bin/env python

# Helps read and process packet capture files (PCAPs)

import collections

from globals import FIELDS
from scapy.all import *

def read_pcap(filename):
	return rdpcap(filename)

def parse_packets(filename):
	results = []
	data = read_pcap(filename)
	if not data:
		return results

	NetworkItem = collections.namedtuple('NetworkItem', ' '.join(FIELDS))
	for datum in data:
		try:
			try:
				src_ip = datum[IP].src
				dst_ip = datum[IP].dst
			except:
				try:
					src_ip = datum[IPv6].src
					dst_ip = datum[IPv6].dst
				except:
					src_ip = p.src
					dst_ip = p.dst
			size = pkt.len

			src_port = datum[TCP].sport
			dst_port = datum[TCP].dport

			protocol = 'unknown'#TODO

			ni = NetworkItem(
				ts = float(p.ts),\
				uid = None,\
				orig_h = src_ip,\
				orig_p = src_port,\
				resp_h = dst_ip,\
				resp_p = dst_port,\
				proto = ,\
				service = 'unknown',\
				duration = 0,\
				orig_bytes = len(size),\
				resp_bytes = None,\
				conn_state = None,\
				local_orig = None,\
				local_resp = None,\
				missed_bytes = 0,\
				history = None,\
				orig_pkts = 1,\
				orig_ip_bytes = len(datum[IP].payload),\
				resp_pkys = None,\
				resp_ip_bytes = None,\
				tunnel_parents = None,\
				type = 'packet',
			)
			results.append(ni)
		except Exception as e:
			print "Error parsing pcap", repr(e)

	return pkts
